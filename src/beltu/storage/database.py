from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterator

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    result TEXT,
    error TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    priority INTEGER NOT NULL DEFAULT 50,
    max_attempts INTEGER NOT NULL DEFAULT 1,
    next_run_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);
CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_tasks_scan_id ON tasks(scan_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    data_json TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    statement TEXT NOT NULL,
    basis_observation_ids_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    hypothesis_id INTEGER,
    action_kind TEXT NOT NULL,
    action_payload_json TEXT NOT NULL DEFAULT '{}',
    rationale TEXT NOT NULL,
    confidence REAL NOT NULL,
    risk_level TEXT NOT NULL,
    requires_approval INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_observations_scan_id ON observations(scan_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_scan_id ON hypotheses(scan_id);
CREATE INDEX IF NOT EXISTS idx_decisions_scan_id ON decisions(scan_id);

CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    action_kind TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    channel TEXT NOT NULL,
    recipient TEXT,
    reason TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT,
    token TEXT NOT NULL,
    FOREIGN KEY (decision_id) REFERENCES decisions(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_decision_id ON approvals(decision_id);
CREATE INDEX IF NOT EXISTS idx_approvals_recipient ON approvals(recipient);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    observation_id INTEGER,
    kind TEXT NOT NULL,
    path TEXT,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (observation_id) REFERENCES observations(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_scan_id ON evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_observation_id ON evidence(observation_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);

CREATE TABLE IF NOT EXISTS observation_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    observation_id INTEGER NOT NULL,
    related_observation_id INTEGER NOT NULL,
    relation TEXT NOT NULL,
    score REAL NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(observation_id, related_observation_id, relation),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (observation_id) REFERENCES observations(id) ON DELETE CASCADE,
    FOREIGN KEY (related_observation_id) REFERENCES observations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_observation_links_scan_id ON observation_links(scan_id);
CREATE INDEX IF NOT EXISTS idx_observation_links_observation_id ON observation_links(observation_id);

CREATE TABLE IF NOT EXISTS reasoning_cycles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    trigger TEXT NOT NULL,
    trigger_task_id INTEGER NOT NULL DEFAULT 0,
    context_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(scan_id, trigger, trigger_task_id, context_fingerprint),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reasoning_cycles_scan_id ON reasoning_cycles(scan_id);
CREATE INDEX IF NOT EXISTS idx_reasoning_cycles_status ON reasoning_cycles(status);
CREATE INDEX IF NOT EXISTS idx_reasoning_cycles_fingerprint ON reasoning_cycles(context_fingerprint);

CREATE TABLE IF NOT EXISTS llm_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    cycle_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    status TEXT NOT NULL,
    prompt_sha256 TEXT NOT NULL,
    response_sha256 TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    response_text TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (cycle_id) REFERENCES reasoning_cycles(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_llm_runs_scan_id ON llm_runs(scan_id);
CREATE INDEX IF NOT EXISTS idx_llm_runs_cycle_id ON llm_runs(cycle_id);

CREATE TABLE IF NOT EXISTS capability_selections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    cycle_id INTEGER,
    decision_id INTEGER,
    capability TEXT NOT NULL,
    tool TEXT,
    score REAL NOT NULL,
    expected_information_gain REAL NOT NULL,
    cost REAL NOT NULL,
    risk_level TEXT NOT NULL,
    rationale TEXT NOT NULL,
    candidates_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (cycle_id) REFERENCES reasoning_cycles(id) ON DELETE SET NULL,
    FOREIGN KEY (decision_id) REFERENCES decisions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_capability_selections_scan_id ON capability_selections(scan_id);
CREATE INDEX IF NOT EXISTS idx_capability_selections_decision_id ON capability_selections(decision_id);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    asset_type TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'discovered',
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(scan_id, normalized_value, asset_type),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_assets_target_id ON assets(target_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_normalized_value ON assets(normalized_value);

CREATE TABLE IF NOT EXISTS asset_relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    parent_asset_id INTEGER NOT NULL,
    child_asset_id INTEGER NOT NULL,
    relation TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(parent_asset_id, child_asset_id, relation),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (child_asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_asset_relations_scan_id ON asset_relations(scan_id);
CREATE INDEX IF NOT EXISTS idx_asset_relations_parent ON asset_relations(parent_asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_relations_child ON asset_relations(child_asset_id);

CREATE TABLE IF NOT EXISTS asset_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    transport TEXT NOT NULL,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    product TEXT,
    version TEXT,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(asset_id, transport, port, service, product, version),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_asset_services_scan_id ON asset_services(scan_id);
CREATE INDEX IF NOT EXISTS idx_asset_services_asset_id ON asset_services(asset_id);

CREATE TABLE IF NOT EXISTS asset_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'UNKNOWN',
    path TEXT NOT NULL,
    endpoint_type TEXT NOT NULL DEFAULT 'web',
    auth_hint TEXT,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(asset_id, url, method),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_asset_endpoints_scan_id ON asset_endpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_asset_endpoints_asset_id ON asset_endpoints(asset_id);

CREATE TABLE IF NOT EXISTS asset_technologies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    category TEXT,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(asset_id, name, version, category),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_asset_technologies_scan_id ON asset_technologies(scan_id);
CREATE INDEX IF NOT EXISTS idx_asset_technologies_asset_id ON asset_technologies(asset_id);

CREATE TABLE IF NOT EXISTS surface_priorities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    value TEXT NOT NULL,
    score REAL NOT NULL,
    priority TEXT NOT NULL,
    exposure REAL NOT NULL,
    novelty REAL NOT NULL,
    sensitivity REAL NOT NULL,
    confidence REAL NOT NULL,
    rationale TEXT NOT NULL,
    signals_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, entity_type, entity_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_surface_priorities_scan_id ON surface_priorities(scan_id);
CREATE INDEX IF NOT EXISTS idx_surface_priorities_score ON surface_priorities(score);
CREATE INDEX IF NOT EXISTS idx_surface_priorities_priority ON surface_priorities(priority);

CREATE TABLE IF NOT EXISTS api_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    endpoint_id INTEGER,
    operation_key TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    operation_id TEXT,
    api_style TEXT NOT NULL DEFAULT 'rest',
    tags_json TEXT NOT NULL DEFAULT '[]',
    auth_required INTEGER NOT NULL DEFAULT 0,
    auth_schemes_json TEXT NOT NULL DEFAULT '[]',
    request_content_types_json TEXT NOT NULL DEFAULT '[]',
    response_content_types_json TEXT NOT NULL DEFAULT '[]',
    summary TEXT,
    description TEXT,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, operation_key),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (endpoint_id) REFERENCES asset_endpoints(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_api_operations_scan_id ON api_operations(scan_id);
CREATE INDEX IF NOT EXISTS idx_api_operations_asset_id ON api_operations(asset_id);
CREATE INDEX IF NOT EXISTS idx_api_operations_path ON api_operations(path);
CREATE INDEX IF NOT EXISTS idx_api_operations_auth ON api_operations(auth_required);

CREATE TABLE IF NOT EXISTS api_parameters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    operation_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    required INTEGER NOT NULL DEFAULT 0,
    parameter_type TEXT,
    schema_json TEXT NOT NULL DEFAULT '{}',
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(operation_id, name, location),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (operation_id) REFERENCES api_operations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_parameters_scan_id ON api_parameters(scan_id);
CREATE INDEX IF NOT EXISTS idx_api_parameters_operation_id ON api_parameters(operation_id);

CREATE TABLE IF NOT EXISTS api_relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    from_operation_id INTEGER NOT NULL,
    to_operation_id INTEGER NOT NULL,
    relation TEXT NOT NULL,
    confidence REAL NOT NULL,
    basis_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(from_operation_id, to_operation_id, relation),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (from_operation_id) REFERENCES api_operations(id) ON DELETE CASCADE,
    FOREIGN KEY (to_operation_id) REFERENCES api_operations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_relations_scan_id ON api_relations(scan_id);
CREATE INDEX IF NOT EXISTS idx_api_relations_from ON api_relations(from_operation_id);

CREATE INDEX IF NOT EXISTS idx_api_relations_to ON api_relations(to_operation_id);

CREATE TABLE IF NOT EXISTS auth_principals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    role TEXT,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, label, role),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_principals_scan_id ON auth_principals(scan_id);
CREATE INDEX IF NOT EXISTS idx_auth_principals_role ON auth_principals(role);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    label TEXT NOT NULL,
    transport TEXT NOT NULL,
    mechanism TEXT NOT NULL,
    state TEXT NOT NULL,
    secure INTEGER,
    http_only INTEGER,
    same_site TEXT,
    domain TEXT,
    path TEXT,
    expires_at TEXT,
    value_present INTEGER NOT NULL DEFAULT 0,
    fingerprint_sha256 TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, label, transport, mechanism),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_scan_id ON auth_sessions(scan_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_fingerprint ON auth_sessions(fingerprint_sha256);

CREATE TABLE IF NOT EXISTS auth_operation_controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    operation_id INTEGER NOT NULL,
    principal_id INTEGER,
    principal_label TEXT NOT NULL,
    access_state TEXT NOT NULL,
    auth_required INTEGER NOT NULL DEFAULT 0,
    schemes_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL,
    basis_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(operation_id, principal_id, access_state),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (operation_id) REFERENCES api_operations(id) ON DELETE CASCADE,
    FOREIGN KEY (principal_id) REFERENCES auth_principals(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_controls_scan_id ON auth_operation_controls(scan_id);
CREATE INDEX IF NOT EXISTS idx_auth_controls_operation_id ON auth_operation_controls(operation_id);
CREATE INDEX IF NOT EXISTS idx_auth_controls_principal_id ON auth_operation_controls(principal_id);

CREATE TABLE IF NOT EXISTS auth_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    operation_id INTEGER,
    relation TEXT NOT NULL,
    confidence REAL NOT NULL,
    basis_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(scan_id, from_state, to_state, operation_id, relation),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (operation_id) REFERENCES api_operations(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_transitions_scan_id ON auth_transitions(scan_id);
CREATE INDEX IF NOT EXISTS idx_auth_transitions_states ON auth_transitions(from_state, to_state);

CREATE TABLE IF NOT EXISTS authorization_matrix (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    operation_id INTEGER NOT NULL,
    principal_id INTEGER,
    principal_key TEXT NOT NULL,
    principal_label TEXT NOT NULL,
    role TEXT,
    access_state TEXT NOT NULL,
    auth_required INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL,
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    basis_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, operation_id, principal_key, access_state),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (operation_id) REFERENCES api_operations(id) ON DELETE CASCADE,
    FOREIGN KEY (principal_id) REFERENCES auth_principals(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_authorization_matrix_scan_id ON authorization_matrix(scan_id);
CREATE INDEX IF NOT EXISTS idx_authorization_matrix_operation_id ON authorization_matrix(operation_id);
CREATE INDEX IF NOT EXISTS idx_authorization_matrix_principal ON authorization_matrix(principal_key);

CREATE TABLE IF NOT EXISTS authorization_anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    statement TEXT NOT NULL,
    rationale TEXT NOT NULL,
    confidence REAL NOT NULL,
    basis_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, kind, entity_type, entity_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_authorization_anomalies_scan_id ON authorization_anomalies(scan_id);
CREATE INDEX IF NOT EXISTS idx_authorization_anomalies_kind ON authorization_anomalies(kind);
CREATE INDEX IF NOT EXISTS idx_authorization_anomalies_severity ON authorization_anomalies(severity);


CREATE TABLE IF NOT EXISTS business_workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    workflow_key TEXT NOT NULL,
    label TEXT NOT NULL,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, workflow_key),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_business_workflows_scan_id ON business_workflows(scan_id);
CREATE INDEX IF NOT EXISTS idx_business_workflows_key ON business_workflows(workflow_key);

CREATE TABLE IF NOT EXISTS workflow_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id INTEGER NOT NULL,
    state_key TEXT NOT NULL,
    label TEXT NOT NULL,
    initial INTEGER NOT NULL DEFAULT 0,
    terminal INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(workflow_id, state_key),
    FOREIGN KEY (workflow_id) REFERENCES business_workflows(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_workflow_states_workflow_id ON workflow_states(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_states_key ON workflow_states(state_key);

CREATE TABLE IF NOT EXISTS workflow_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    workflow_id INTEGER NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    operation_id INTEGER,
    relation TEXT NOT NULL,
    action TEXT,
    confidence REAL NOT NULL,
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    basis_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(workflow_id, from_state, to_state, operation_id, relation),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (workflow_id) REFERENCES business_workflows(id) ON DELETE CASCADE,
    FOREIGN KEY (operation_id) REFERENCES api_operations(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_workflow_transitions_scan_id ON workflow_transitions(scan_id);
CREATE INDEX IF NOT EXISTS idx_workflow_transitions_workflow_id ON workflow_transitions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_transitions_from_state ON workflow_transitions(from_state);
CREATE INDEX IF NOT EXISTS idx_workflow_transitions_to_state ON workflow_transitions(to_state);

CREATE TABLE IF NOT EXISTS business_logic_anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    workflow_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    statement TEXT NOT NULL,
    rationale TEXT NOT NULL,
    confidence REAL NOT NULL,
    entity_key TEXT NOT NULL,
    basis_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'candidate',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, workflow_id, kind, entity_key),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (workflow_id) REFERENCES business_workflows(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_business_logic_anomalies_scan_id ON business_logic_anomalies(scan_id);
CREATE INDEX IF NOT EXISTS idx_business_logic_anomalies_workflow_id ON business_logic_anomalies(workflow_id);
CREATE INDEX IF NOT EXISTS idx_business_logic_anomalies_kind ON business_logic_anomalies(kind);
CREATE INDEX IF NOT EXISTS idx_business_logic_anomalies_severity ON business_logic_anomalies(severity);

CREATE TABLE IF NOT EXISTS finding_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'candidate',
    subject TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    impact_summary TEXT NOT NULL,
    rationale TEXT NOT NULL,
    source_count INTEGER NOT NULL DEFAULT 0,
    corroboration_score REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, fingerprint),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_finding_candidates_scan_id ON finding_candidates(scan_id);
CREATE INDEX IF NOT EXISTS idx_finding_candidates_status ON finding_candidates(status);
CREATE INDEX IF NOT EXISTS idx_finding_candidates_fingerprint ON finding_candidates(fingerprint);
CREATE INDEX IF NOT EXISTS idx_finding_candidates_severity ON finding_candidates(severity);

CREATE TABLE IF NOT EXISTS finding_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    source_type TEXT NOT NULL,
    source_id INTEGER NOT NULL,
    relation TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(finding_id, source_type, source_id, relation),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES finding_candidates(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_finding_sources_finding_id ON finding_sources(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_sources_source ON finding_sources(source_type, source_id);

CREATE TABLE IF NOT EXISTS validation_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    objective TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    risk_level TEXT NOT NULL,
    requires_approval INTEGER NOT NULL DEFAULT 1,
    preconditions_json TEXT NOT NULL DEFAULT '[]',
    expected_evidence_json TEXT NOT NULL DEFAULT '[]',
    stop_conditions_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL,
    rationale TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(finding_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES finding_candidates(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_validation_plans_scan_id ON validation_plans(scan_id);
CREATE INDEX IF NOT EXISTS idx_validation_plans_status ON validation_plans(status);

CREATE TABLE IF NOT EXISTS validation_plan_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    step_kind TEXT NOT NULL,
    title TEXT NOT NULL,
    instruction TEXT NOT NULL,
    expected_observation_kind TEXT,
    approval_required INTEGER NOT NULL DEFAULT 1,
    risk_level TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(plan_id, ordinal),
    FOREIGN KEY (plan_id) REFERENCES validation_plans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_validation_plan_steps_plan_id ON validation_plan_steps(plan_id);

CREATE TABLE IF NOT EXISTS report_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    report_type TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    generation_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(scan_id, report_type),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_report_packages_scan_id ON report_packages(scan_id);
CREATE INDEX IF NOT EXISTS idx_report_packages_type ON report_packages(report_type);

CREATE TABLE IF NOT EXISTS report_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(package_id, relative_path),
    FOREIGN KEY (package_id) REFERENCES report_packages(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_report_files_package_id ON report_files(package_id);

CREATE TABLE IF NOT EXISTS remote_chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    direction TEXT NOT NULL,
    body TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remote_chat_conversation ON remote_chat_messages(conversation_id, id);

CREATE TABLE IF NOT EXISTS remote_audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remote_audit_created_at ON remote_audit_events(created_at);

"""

# Additive migrations keep Stage-1 databases upgradeable without destructive changes.
_DECISION_MIGRATIONS = {
    "cycle_id": "INTEGER",
    "action_fingerprint": "TEXT",
    "superseded_at": "TEXT",
    "superseded_reason": "TEXT",
}


_TASK_MIGRATIONS = {
    "payload": "TEXT NOT NULL DEFAULT '{}'",
    "result": "TEXT",
    "error": "TEXT",
    "attempts": "INTEGER NOT NULL DEFAULT 0",
    "started_at": "TEXT",
    "finished_at": "TEXT",
    "priority": "INTEGER NOT NULL DEFAULT 50",
    "max_attempts": "INTEGER NOT NULL DEFAULT 1",
    "next_run_at": "TEXT",
}


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            existing_tasks = {
                row[1] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()
            }
            for name, ddl in _TASK_MIGRATIONS.items():
                if name not in existing_tasks:
                    conn.execute(f"ALTER TABLE tasks ADD COLUMN {name} {ddl}")
            existing_decisions = {
                row[1] for row in conn.execute("PRAGMA table_info(decisions)").fetchall()
            }
            for name, ddl in _DECISION_MIGRATIONS.items():
                if name not in existing_decisions:
                    conn.execute(f"ALTER TABLE decisions ADD COLUMN {name} {ddl}")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_decisions_action_fingerprint ON decisions(action_fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_decisions_cycle_id ON decisions(cycle_id)")

    def transaction(self) -> Iterator[sqlite3.Connection]:
        return self.connect()
