from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable


class SmtpReportDelivery:
    def __init__(self, project_root: str | Path = ".") -> None:
        self.project_root = Path(project_root).resolve()
        self.host = os.getenv("BELTU_SMTP_HOST", "")
        self.port = int(os.getenv("BELTU_SMTP_PORT", "465"))
        self.user = os.getenv("BELTU_SMTP_USER", "")
        self.password = os.getenv("BELTU_SMTP_PASSWORD", "")
        self.sender = os.getenv("BELTU_SMTP_FROM", self.user)
        self.use_ssl = os.getenv("BELTU_SMTP_SSL", "true").lower() in {"1", "true", "yes"}

    def configured(self) -> bool:
        return bool(self.host and self.sender)

    def send(self, *, recipient: str, subject: str, body: str, attachments: Iterable[tuple[str, bytes, str]]) -> None:
        if not self.configured():
            raise RuntimeError("SMTP is not configured")
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.set_content(body)
        for filename, content, mime in attachments:
            maintype, _, subtype = mime.partition("/")
            msg.add_attachment(content, maintype=maintype or "application", subtype=subtype or "octet-stream", filename=filename)
        smtp_cls = smtplib.SMTP_SSL if self.use_ssl else smtplib.SMTP
        with smtp_cls(self.host, self.port, timeout=20) as smtp:
            if not self.use_ssl:
                smtp.starttls()
            if self.user:
                smtp.login(self.user, self.password)
            smtp.send_message(msg)
