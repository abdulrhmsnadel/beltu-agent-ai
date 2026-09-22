from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response

from beltu.common.types import Event
from beltu.control.approval_service import ApprovalService
from beltu.core.event_bus import EventBus
from beltu.remote.auth import RemoteAuth, RemotePrincipal
from beltu.remote.delivery import SmtpReportDelivery
from beltu.remote.events import EventHub
from beltu.remote.repository import RemoteRepository
from beltu.remote.schemas import ChatMessageRequest, ChatMessageResponse, LoginRequest, LoginResponse
from beltu.remote.workspace import WorkspaceService
from beltu.remote.chat_bridge import ChatAgentBridge
from beltu.storage.database import Database
from beltu.storage.repositories.approval_repository import ApprovalRepository
from beltu.storage.repositories.decision_repository import DecisionRepository
from beltu.storage.repositories.report_repository import ReportRepository
from beltu.storage.repositories.task_repository import TaskRepository


def _auth_from_env() -> RemoteAuth:
    return RemoteAuth(
        username=os.getenv("BELTU_REMOTE_USER", "beltu"),
        password=os.getenv("BELTU_REMOTE_PASSWORD", ""),
        secret=os.getenv("BELTU_REMOTE_SECRET", ""),
        ttl_seconds=int(os.getenv("BELTU_REMOTE_TTL_SECONDS", "43200")),
        scopes=tuple(x.strip() for x in os.getenv("BELTU_REMOTE_SCOPES", "read,chat,control,approve").split(",") if x.strip()),
    )


def create_app(project_root: str | Path = ".", *, event_bus: EventBus | None = None, auth: RemoteAuth | None = None, orchestrator: Any | None = None) -> FastAPI:
    root = Path(project_root).resolve()
    db = Database(root / "data" / "beltu.db")
    db.initialize()
    remote_repo = RemoteRepository(db)
    workspace = WorkspaceService(db, root)
    event_hub = EventHub(event_bus)
    authenticator = auth if auth is not None else None
    smtp = SmtpReportDelivery(root)
    if event_bus is not None:
        ChatAgentBridge(event_bus, remote_repo, db).install()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await event_hub.start()
        yield

    app = FastAPI(title="BELTU Remote Operations API", version=__import__("beltu.version", fromlist=["__version__"]).__version__, lifespan=lifespan)
    allowed_origins = [x.strip() for x in os.getenv("BELTU_REMOTE_CORS", "").split(",") if x.strip()]
    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
        )

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def require_auth(authorization: Annotated[str | None, Header()] = None) -> RemotePrincipal:
        if authenticator is None:
            raise HTTPException(status_code=503, detail="Remote authentication is not configured")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Bearer token required")
        try:
            return authenticator.verify(authorization[7:].strip())
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def require_scope(scope: str):
        def checker(principal: RemotePrincipal = Depends(require_auth)) -> RemotePrincipal:
            if scope not in principal.scopes:
                raise HTTPException(status_code=403, detail=f"Missing scope: {scope}")
            return principal
        return checker

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "beltu-remote", "version": __import__("beltu.version", fromlist=["__version__"]).__version__, "auth_configured": authenticator is not None}

    @app.post("/v1/auth/login", response_model=LoginResponse)
    async def login(payload: LoginRequest):
        if authenticator is None:
            raise HTTPException(status_code=503, detail="Remote authentication is not configured")
        try:
            token = authenticator.login(payload.username, payload.password)
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return LoginResponse(access_token=token, expires_in=authenticator.ttl_seconds, scopes=["read", "chat", "control", "approve"])

    @app.get("/v1/targets")
    async def targets(_: RemotePrincipal = Depends(require_scope("read"))):
        with db.connect() as conn:
            rows = conn.execute("SELECT id,value,status,created_at,updated_at FROM targets ORDER BY id").fetchall()
        return {"items": [dict(r) for r in rows]}

    @app.get("/v1/scans")
    async def scans(_: RemotePrincipal = Depends(require_scope("read"))):
        with db.connect() as conn:
            rows = conn.execute("SELECT s.id,s.target_id,t.value AS target,s.status,s.created_at,s.updated_at FROM scans s JOIN targets t ON t.id=s.target_id ORDER BY s.id DESC").fetchall()
        return {"items": [dict(r) for r in rows]}

    @app.get("/v1/system/resources")
    async def system_resources(_: RemotePrincipal = Depends(require_scope("read"))):
        from beltu.execution.resource_governor import ResourceGovernor
        governor = ResourceGovernor(
            2, 30, 30, 1, 0.5,
            freetoken_pid_file=root / "data" / "runtime" / "freetoken.pid",
            freetoken_url=os.getenv("BELTU_FREETOKEN_URL", "http://127.0.0.1:8000"),
            gpu_vram_budget_percent=45,
        )
        snap = governor.snapshot()
        payload = {
            "timestamp": snap.timestamp,
            "beltu": {"cpu_percent": snap.beltu_cpu_percent, "memory_percent": snap.beltu_memory_percent, "rss_bytes": snap.beltu_rss_bytes},
            "host": {"cpu_percent": snap.host_cpu_percent, "memory_percent": snap.host_memory_percent, "load1": snap.load1, "cpu_count": snap.cpu_count},
            "gpu": None if snap.gpu is None else {
                "available": snap.gpu.available, "name": snap.gpu.name, "total_bytes": snap.gpu.total_bytes, "used_bytes": snap.gpu.used_bytes, "free_bytes": snap.gpu.free_bytes, "used_percent": snap.gpu.used_percent, "freetoken_used_bytes": snap.gpu.freetoken_used_bytes, "freetoken_percent": snap.gpu.freetoken_percent,
            },
            "freetoken": None if snap.freetoken is None else {
                "configured": snap.freetoken.configured, "reachable": snap.freetoken.reachable, "pid": snap.freetoken.pid, "model": snap.freetoken.model, "cpu_percent": snap.freetoken.cpu_percent, "rss_bytes": snap.freetoken.rss_bytes, "vram_bytes": snap.freetoken.vram_bytes, "moe_backend": snap.freetoken.moe_backend, "requests": snap.freetoken.requests,
            },
            "adaptive_process_capacity": governor.effective_capacity(snap),
            "tool_limits": {tool: governor.tool_runtime_limits(tool).__dict__ if hasattr(governor.tool_runtime_limits(tool), "__dict__") else {"thread_limit": governor.tool_runtime_limits(tool).thread_limit, "max_parallel_processes": governor.tool_runtime_limits(tool).max_parallel_processes, "reason": governor.tool_runtime_limits(tool).reason} for tool in ("subfinder", "httpx", "nmap", "nuclei")},
        }
        return payload

    @app.get("/v1/scans/{scan_id}/activity")
    async def activity(scan_id: int, limit: int = Query(100, ge=1, le=500), _: RemotePrincipal = Depends(require_scope("read"))):
        with db.connect() as conn:
            out = {
                "tasks": [dict(r) for r in conn.execute("SELECT id,kind,status,priority,attempts,created_at,updated_at,started_at,finished_at,error FROM tasks WHERE scan_id=? ORDER BY id DESC LIMIT ?", (scan_id, limit)).fetchall()],
                "reasoning_cycles": [dict(r) for r in conn.execute("SELECT id,trigger,status,created_at,completed_at,summary_json FROM reasoning_cycles WHERE scan_id=? ORDER BY id DESC LIMIT ?", (scan_id, limit)).fetchall()],
                "decisions": [dict(r) for r in conn.execute("SELECT id,hypothesis_id,action_kind,rationale,confidence,risk_level,requires_approval,status,created_at FROM decisions WHERE scan_id=? ORDER BY id DESC LIMIT ?", (scan_id, limit)).fetchall()],
            }
        remote_repo.audit(actor="api", action="view_activity", resource=f"scan:{scan_id}")
        return out

    @app.get("/v1/scans/{scan_id}/findings")
    async def findings(scan_id: int, _: RemotePrincipal = Depends(require_scope("read"))):
        with db.connect() as conn:
            rows = conn.execute("SELECT id,title,category,severity,confidence,status,subject,impact_summary,rationale,created_at,updated_at FROM finding_candidates WHERE scan_id=? ORDER BY confidence DESC,id", (scan_id,)).fetchall()
        return {"items": [dict(r) for r in rows]}

    @app.get("/v1/scans/{scan_id}/reports")
    async def reports(scan_id: int, _: RemotePrincipal = Depends(require_scope("read"))):
        repo = ReportRepository(db)
        items = []
        for package in repo.list_packages(scan_id):
            items.append({
                "id": package.id,
                "report_type": package.report_type,
                "relative_path": package.relative_path,
                "sha256": package.sha256,
                "size_bytes": package.size_bytes,
                "created_at": package.created_at,
                "files": [{"id": f.id, "kind": f.kind, "relative_path": f.relative_path, "sha256": f.sha256, "size_bytes": f.size_bytes, "mime_type": f.mime_type, "created_at": f.created_at} for f in repo.list_files(package.id)],
            })
        remote_repo.audit(actor="api", action="list_reports", resource=f"scan:{scan_id}")
        return {"items": items}

    @app.post("/v1/scans/{scan_id}/reports/send", dependencies=[Depends(require_scope("control"))])
    async def send_reports(scan_id: int, recipient: str = Query(..., min_length=3, max_length=320), report_types: str = Query("full_package", max_length=500), principal: RemotePrincipal = Depends(require_scope("control"))):
        repo = ReportRepository(db)
        wanted = {x.strip() for x in report_types.split(",") if x.strip()}
        packages = [p for p in repo.list_packages(scan_id) if p.report_type in wanted]
        if not packages:
            raise HTTPException(status_code=404, detail="No matching report packages")
        attachments = []
        for package in packages:
            path = (workspace.workspace_root(scan_id) / package.relative_path).resolve()
            root_path = workspace.workspace_root(scan_id)
            if root_path not in path.parents and path != root_path:
                raise HTTPException(status_code=403, detail="Report path escapes workspace")
            if not path.is_file():
                raise HTTPException(status_code=404, detail=f"Missing package: {package.report_type}")
            attachments.append((path.name, path.read_bytes(), "application/zip" if path.suffix == ".zip" else "text/markdown"))
        try:
            smtp.send(recipient=recipient, subject=f"BELTU reports — scan #{scan_id}", body=f"BELTU report delivery for scan #{scan_id}. Attachments: {', '.join(p.report_type for p in packages)}", attachments=attachments)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        audit_id = remote_repo.audit(actor=principal.subject, action="send_reports", resource=f"scan:{scan_id}", metadata={"recipient": recipient, "report_types": sorted(wanted)})
        return {"status": "sent", "audit_id": audit_id, "report_types": [p.report_type for p in packages]}

    @app.get("/v1/approvals")
    async def approvals(_: RemotePrincipal = Depends(require_scope("approve"))):
        rows = ApprovalRepository(db).list_pending()
        return {"items": [{"id": a.id, "decision_id": a.decision_id, "scan_id": a.scan_id, "action_kind": a.action_kind, "status": a.status, "channel": a.channel, "recipient": a.recipient, "reason": a.reason, "requested_at": a.requested_at, "expires_at": a.expires_at} for a in rows]}

    @app.post("/v1/approvals/{approval_id}/approve")
    async def approve(approval_id: int, token: str = Query(..., min_length=8, max_length=256), principal: RemotePrincipal = Depends(require_scope("approve"))):
        service = ApprovalService(DecisionRepository(db), ApprovalRepository(db))
        try:
            approval = service.approve(approval_id, resolved_by=f"mobile:{principal.subject}", token=token)
        except (KeyError, PermissionError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        queued_task_id = None
        decision = DecisionRepository(db).get(approval.decision_id)
        if decision is not None and orchestrator is not None:
            tasks = TaskRepository(db)
            existing = tasks.list_for_decision(decision.scan_id, decision.id)
            active = [item for item in existing if item.status in {"pending", "running"}]
            if not active:
                task = tasks.create(
                    decision.scan_id,
                    "capability.execute",
                    {"decision_id": decision.id},
                    priority=80,
                    max_attempts=2,
                )
                await orchestrator.scheduler.enqueue(task)
                queued_task_id = task.id

        audit_id = remote_repo.audit(
            actor=principal.subject,
            action="approve",
            resource=f"approval:{approval_id}",
            metadata={"decision_id": approval.decision_id, "queued_task_id": queued_task_id},
        )
        event = Event(
            "remote.approval.resolved",
            {"approval_id": approval_id, "status": "approved", "decision_id": approval.decision_id, "queued_task_id": queued_task_id},
            remote_repo.__class__.__name__,
        )
        if event_bus is not None:
            await event_bus.publish(event.type, event.payload)
        else:
            await event_hub._on_event(event)
        return {"status": approval.status, "approval_id": approval.id, "decision_id": approval.decision_id, "queued_task_id": queued_task_id, "audit_id": audit_id}

    @app.post("/v1/approvals/{approval_id}/reject")
    async def reject(approval_id: int, principal: RemotePrincipal = Depends(require_scope("approve"))):
        service = ApprovalService(DecisionRepository(db), ApprovalRepository(db))
        try:
            approval = service.reject(approval_id, resolved_by=f"mobile:{principal.subject}")
        except (KeyError, PermissionError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        audit_id = remote_repo.audit(actor=principal.subject, action="reject", resource=f"approval:{approval_id}")
        event = Event("remote.approval.resolved", {"approval_id": approval_id, "status": "rejected"}, remote_repo.__class__.__name__)
        if event_bus is not None:
            await event_bus.publish(event.type, event.payload)
        else:
            await event_hub._on_event(event)
        return {"status": approval.status, "approval_id": approval.id, "audit_id": audit_id}

    @app.post("/v1/scans/{scan_id}/pause")
    async def pause_scan(scan_id: int, principal: RemotePrincipal = Depends(require_scope("control"))):
        if orchestrator is not None:
            changed = await orchestrator.pause_scan(scan_id)
        else:
            with db.connect() as conn:
                cur = conn.execute("UPDATE scans SET status='paused', updated_at=datetime('now') WHERE id=? AND status IN ('pending','running')", (scan_id,))
            changed = cur.rowcount == 1
        if not changed:
            raise HTTPException(status_code=409, detail="Scan cannot be paused from its current state")
        audit_id = remote_repo.audit(actor=principal.subject, action="pause_scan", resource=f"scan:{scan_id}")
        return {"status": "paused", "scan_id": scan_id, "audit_id": audit_id}

    @app.post("/v1/scans/{scan_id}/resume")
    async def resume_scan(scan_id: int, principal: RemotePrincipal = Depends(require_scope("control"))):
        if orchestrator is not None:
            changed = await orchestrator.resume_scan(scan_id)
        else:
            with db.connect() as conn:
                cur = conn.execute("UPDATE scans SET status='running', updated_at=datetime('now') WHERE id=? AND status IN ('paused','failed','pending')", (scan_id,))
            changed = cur.rowcount == 1
        if not changed:
            raise HTTPException(status_code=409, detail="Scan cannot be resumed from its current state")
        audit_id = remote_repo.audit(actor=principal.subject, action="resume_scan", resource=f"scan:{scan_id}")
        return {"status": "running", "scan_id": scan_id, "audit_id": audit_id}

    @app.get("/v1/scans/{scan_id}/files")
    async def files(scan_id: int, path: str = Query("", max_length=500), _: RemotePrincipal = Depends(require_scope("read"))):
        try:
            items = workspace.list_path(scan_id, path)
        except (KeyError, FileNotFoundError, PermissionError) as exc:
            raise HTTPException(status_code=404 if isinstance(exc, (KeyError, FileNotFoundError)) else 403, detail=str(exc)) from exc
        return {"path": path, "items": items}

    @app.get("/v1/scans/{scan_id}/files/content")
    async def file_content(scan_id: int, path: str = Query(..., min_length=1, max_length=500), _: RemotePrincipal = Depends(require_scope("read"))):
        try:
            _, data, mime = workspace.read_file(scan_id, path)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        remote_repo.audit(actor="api", action="read_file", resource=f"scan:{scan_id}:{path}")
        return Response(content=data, media_type=mime, headers={"Content-Disposition": "inline"})

    @app.get("/v1/scans/{scan_id}/files/download")
    async def file_download(scan_id: int, path: str = Query(..., min_length=1, max_length=500), principal: RemotePrincipal = Depends(require_scope("read"))):
        try:
            file_path, _, mime = workspace.read_file(scan_id, path, max_bytes=100_000_000)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        audit_id = remote_repo.audit(actor=principal.subject, action="download_file", resource=f"scan:{scan_id}:{path}")
        return FileResponse(file_path, media_type=mime, filename=file_path.name, headers={"X-BELTU-Audit-ID": str(audit_id), "Cache-Control": "no-store"})

    @app.get("/v1/chat/{conversation_id}")
    async def chat_history(conversation_id: str, limit: int = Query(100, ge=1, le=500), _: RemotePrincipal = Depends(require_scope("chat"))):
        return {"items": remote_repo.list_chat(conversation_id, limit)}

    @app.post("/v1/chat/messages", response_model=ChatMessageResponse)
    async def chat_message(payload: ChatMessageRequest, principal: RemotePrincipal = Depends(require_scope("chat"))):
        message_id = remote_repo.add_chat(conversation_id=payload.conversation_id, sender=principal.subject, direction="inbound", body=payload.body, metadata=payload.metadata)
        event = Event("remote.chat.message", {"message_id": message_id, "conversation_id": payload.conversation_id, "body": payload.body, "sender": principal.subject, "direction": "inbound"}, "")
        if event_bus is not None:
            await event_bus.publish(event.type, event.payload)
        else:
            await event_hub._on_event(event)
        remote_repo.audit(actor=principal.subject, action="send_chat_message", resource=f"conversation:{payload.conversation_id}")
        history = remote_repo.list_chat(payload.conversation_id, 500)
        return next(item for item in history if int(item["id"]) == message_id)

    @app.websocket("/v1/ws/events")
    async def events(websocket: WebSocket):
        await websocket.accept()
        token = websocket.query_params.get("token", "")
        if authenticator is None:
            await websocket.close(code=1013, reason="Remote authentication is not configured")
            return
        try:
            principal = authenticator.verify(token)
            if "read" not in principal.scopes:
                raise PermissionError("Missing scope: read")
        except PermissionError:
            await websocket.close(code=1008, reason="Unauthorized")
            return
        queue = await event_hub.subscribe()
        try:
            await websocket.send_json({"type": "remote.connected", "payload": {"subject": principal.subject}})
            while True:
                message = await queue.get()
                await websocket.send_json(message)
        except WebSocketDisconnect:
            pass
        finally:
            await event_hub.unsubscribe(queue)

    return app
