from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scopes: list[str]


class ApprovalResolutionRequest(BaseModel):
    token: str = Field(min_length=8, max_length=256)


class ChatMessageRequest(BaseModel):
    conversation_id: str = Field(min_length=1, max_length=128)
    body: str = Field(min_length=1, max_length=4000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChatMessageResponse(BaseModel):
    id: int
    conversation_id: str
    sender: str
    direction: str
    body: str
    metadata: dict[str, Any]
    created_at: str


class AuditResponse(BaseModel):
    status: str
    audit_id: int
