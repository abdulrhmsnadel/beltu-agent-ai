from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest

from beltu.control.approval_service import ApprovalService
from beltu.integrations.whatsapp.message_router import parse_approval_command
from beltu.integrations.whatsapp.notifier import format_approval_request
from beltu.integrations.whatsapp.security import verify_meta_signature
from beltu.integrations.whatsapp.webhook import WhatsAppWebhookHandler
from beltu.storage.database import Database
from beltu.storage.repositories.approval_repository import ApprovalRepository, canonical_action_hash
from beltu.storage.repositories.decision_repository import DecisionRepository


def seeded(tmp_path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    with db.connect() as conn:
        conn.execute("INSERT INTO targets(value,status,created_at,updated_at) VALUES('authorized.test','new','x','x')")
        conn.execute("INSERT INTO scans(target_id,status,created_at,updated_at) VALUES(1,'running','x','x')")
    decisions = DecisionRepository(db)
    approvals = ApprovalRepository(db)
    decision = decisions.create(
        1, None, "service_enrichment", {"target": "authorized.test"},
        "Need active enrichment", 0.8, "medium", True, "accepted"
    )
    return db, decisions, approvals, decision


def test_approval_bindings_and_token(tmp_path):
    db, decisions, approvals, decision = seeded(tmp_path)
    service = ApprovalService(decisions, approvals)
    req = service.request_for_decision(decision.id, channel="cli", recipient="operator")
    assert req.status == "pending"
    assert req.action_hash == canonical_action_hash(decision.id, decision.action_kind, decision.action_payload)
    with pytest.raises(PermissionError):
        service.approve(req.id, resolved_by="cli:test", token="wrong")
    approved = service.approve(req.id, resolved_by="cli:test", token=req.token)
    assert approved.status == "approved"
    assert decisions.get(decision.id).status == "approved"
    assert service.revalidate_approval(req.id)


def test_reject_is_persistent(tmp_path):
    db, decisions, approvals, decision = seeded(tmp_path)
    service = ApprovalService(decisions, approvals)
    req = service.request_for_decision(decision.id, channel="cli", recipient="operator")
    rejected = service.reject(req.id, resolved_by="cli:test", token=req.token)
    assert rejected.status == "rejected"
    assert decisions.get(decision.id).status == "rejected"


def test_expired_approval_is_rejected(tmp_path):
    db, decisions, approvals, decision = seeded(tmp_path)
    now = datetime.now(timezone.utc)
    action_hash = canonical_action_hash(decision.id, decision.action_kind, decision.action_payload)
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO approvals(decision_id,scan_id,action_kind,action_hash,status,channel,recipient,reason,requested_at,expires_at,token) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (decision.id, 1, decision.action_kind, action_hash, "pending", "cli", "operator", "expired", now.isoformat(), (now - timedelta(seconds=1)).isoformat(), "tok"),
        )
    service = ApprovalService(decisions, approvals)
    with pytest.raises(ValueError, match="expired"):
        service.approve(1, resolved_by="cli:test", token="tok")
    assert approvals.get(1).status == "expired"


def test_action_hash_detects_decision_mutation(tmp_path):
    db, decisions, approvals, decision = seeded(tmp_path)
    service = ApprovalService(decisions, approvals)
    req = service.request_for_decision(decision.id, channel="cli", recipient="operator")
    with db.connect() as conn:
        conn.execute("UPDATE decisions SET action_payload_json=? WHERE id=?", (json.dumps({"target": "different.test"}), decision.id))
    with pytest.raises(ValueError, match="changed"):
        service.approve(req.id, resolved_by="cli:test", token=req.token)


def test_whatsapp_command_parser():
    assert parse_approval_command("YES 42 abc-123").approval_id == 42
    assert parse_approval_command("NO 9") is not None
    assert parse_approval_command("hello") is None


def test_meta_signature_verification():
    body = b'{"entry":[]}'
    secret = "app-secret"
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_meta_signature(body, f"sha256={digest}", secret)
    assert not verify_meta_signature(body, "sha256=bad", secret)


def test_whatsapp_webhook_requires_authorized_sender(tmp_path):
    db, decisions, approvals, decision = seeded(tmp_path)
    service = ApprovalService(decisions, approvals)
    req = service.request_for_decision(decision.id, channel="whatsapp", recipient="201000000000", ttl_seconds=600)
    handler = WhatsAppWebhookHandler(service, verify_token="verify", app_secret="secret", controller_numbers={"201000000000"})
    payload = {"entry": [{"changes": [{"value": {"messages": [{"from": "201000000000", "text": {"body": f"YES {req.id} {req.token}"}}]}}]}]}
    body = json.dumps(payload).encode()
    digest = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    responses = handler.handle(body, f"sha256={digest}")
    assert "APPROVED" in responses[0]["text"]


def test_whatsapp_webhook_blocks_unknown_sender(tmp_path):
    db, decisions, approvals, decision = seeded(tmp_path)
    service = ApprovalService(decisions, approvals)
    req = service.request_for_decision(decision.id, channel="whatsapp", recipient="201000000000")
    handler = WhatsAppWebhookHandler(service, verify_token="verify", app_secret="secret", controller_numbers={"201000000000"})
    payload = {"entry": [{"changes": [{"value": {"messages": [{"from": "209999999999", "text": {"body": f"YES {req.id} {req.token}"}}]}}]}]}
    body = json.dumps(payload).encode()
    digest = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    responses = handler.handle(body, f"sha256={digest}")
    assert responses[0]["text"] == "Unauthorized controller."
    assert approvals.get(req.id).status == "pending"


def test_webhook_verification_challenge(tmp_path):
    db, decisions, approvals, decision = seeded(tmp_path)
    service = ApprovalService(decisions, approvals)
    handler = WhatsAppWebhookHandler(service, verify_token="verify", app_secret="secret", controller_numbers={"1"})
    assert handler.verify_challenge("subscribe", "verify", "challenge-123") == "challenge-123"
    with pytest.raises(PermissionError):
        handler.verify_challenge("subscribe", "wrong", "challenge-123")


def test_whatsapp_approval_message_contains_exact_binding(tmp_path):
    db, decisions, approvals, decision = seeded(tmp_path)
    service = ApprovalService(decisions, approvals)
    req = service.request_for_decision(decision.id, channel="whatsapp", recipient="201000000000")
    message = format_approval_request(req)
    assert f"YES {req.id} {req.token}" in message
    assert f"Decision: #{decision.id}" in message
