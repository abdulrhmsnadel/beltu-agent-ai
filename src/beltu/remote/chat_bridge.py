from __future__ import annotations

from beltu.core.event_bus import EventBus
from beltu.remote.repository import RemoteRepository
from beltu.storage.database import Database
from beltu.storage.repositories.scan_repository import ScanRepository

class ChatAgentBridge:
    """Bounded read-only chat responder for the remote command center."""
    def __init__(self, events: EventBus, remote_repo: RemoteRepository, db: Database):
        self.events = events
        self.remote_repo = remote_repo
        self.scans = ScanRepository(db)

    def install(self) -> None:
        self.events.subscribe_sync("remote.chat.message", self.handle)

    async def handle(self, event) -> None:
        if event.payload.get("direction") != "inbound":
            return
        body = str(event.payload.get("body", "")).strip().lower()
        conversation = str(event.payload.get("conversation_id", ""))
        if body == "help":
            reply = "Read-only chat commands: status | scans | scan <id>"
        elif body == "status":
            with self.scans.db.connect() as conn:
                total = int(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])
            reply = f"BELTU: {len(self.scans.list_resumable())} resumable scans; {total} total scans."
        elif body == "scans":
            with self.scans.db.connect() as conn:
                rows = conn.execute("SELECT id,status FROM scans ORDER BY id DESC LIMIT 10").fetchall()
            reply = "Scans: " + ", ".join(f"#{row[0]}:{row[1]}" for row in reversed(rows)) if rows else "Scans: none"
        elif body.startswith("scan "):
            try:
                scan_id = int(body.split()[1])
                scan = self.scans.get(scan_id)
            except (ValueError, IndexError):
                scan = None
            reply = f"Scan #{scan_id}: {scan.status}" if scan else "Scan not found."
        else:
            return
        self.remote_repo.add_chat(conversation_id=conversation, sender="beltu-agent", direction="outbound", body=reply, metadata={"source":"chat_bridge"})
        await self.events.publish("remote.chat.reply", {"conversation_id": conversation, "body": reply, "source":"chat_bridge"})
