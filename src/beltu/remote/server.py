from __future__ import annotations

import asyncio
import os
from pathlib import Path

import uvicorn

from beltu.remote.app import _auth_from_env, create_app


async def _serve_async(*, host: str, port: int, project_root: str) -> None:
    # Import lazily to keep the remote package independently testable.
    from beltu.interface.cli.app import build_components

    _, _, _, orchestrator, _, _, _ = build_components()
    await orchestrator.start()
    app = create_app(project_root, event_bus=orchestrator.events, auth=_auth_from_env(), orchestrator=orchestrator)
    config = uvicorn.Config(app, host=host, port=port, server_header=False, date_header=False, log_level=os.getenv("BELTU_REMOTE_LOG_LEVEL", "info"))
    server = uvicorn.Server(config)
    try:
        await server.serve()
    finally:
        await orchestrator.stop()


def serve(*, host: str = "127.0.0.1", port: int = 8765, project_root: str = ".") -> None:
    asyncio.run(_serve_async(host=host, port=port, project_root=project_root))
