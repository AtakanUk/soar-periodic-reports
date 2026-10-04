"""SMTP delivery with optional basic or OAuth2 (XOAUTH2) authentication.

OAuth2 uses the Microsoft identity platform refresh-token flow, which is what
Exchange Online requires once basic SMTP AUTH is disabled for a mailbox.
"""

from __future__ import annotations

import base64
import logging
import mimetypes
import smtplib
import ssl
from collections.abc import Iterable
from email.message import EmailMessage
from pathlib import Path

import requests

from .config import MailSettings

log = logging.getLogger(__name__)

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
SMTP_SCOPE = "offline_access https://outlook.office365.com/SMTP.Send"


class MailError(RuntimeError):
    pass


def fetch_access_token(settings: MailSettings, session: requests.Session | None = None) -> str:
    http = session or requests
    response = http.post(
        TOKEN_URL.format(tenant=settings.oauth_tenant_id),
        data={
            "client_id": settings.oauth_client_id,
            "client_secret": settings.oauth_client_secret,
            "refresh_token": settings.oauth_refresh_token,
            "grant_type": "refresh_token",
            "scope": SMTP_SCOPE,
        },
        timeout=30,
    )
    if response.status_code != 200:
        raise MailError(
            f"Token refresh failed with HTTP {response.status_code}: {response.text[:300]}"
        )
    return response.json()["access_token"]


def xoauth2_string(user: str, access_token: str) -> str:
    raw = f"user={user}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def build_message(
    settings: MailSettings,
    subject: str,
    html_body: str | None = None,
    text_body: str | None = None,
    attachments: Iterable[Path] = (),
) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.sender
    message["To"] = ", ".join(settings.recipients)
    if settings.cc:
        message["Cc"] = ", ".join(settings.cc)

    message.set_content(text_body or "This message contains an HTML report.")
    if html_body:
        message.add_alternative(html_body, subtype="html")
    for path in attachments:
        ctype, _ = mimetypes.guess_type(path.name)
        maintype, subtype = (ctype or "application/octet-stream").split("/", 1)
        message.add_attachment(
            path.read_bytes(), maintype=maintype, subtype=subtype, filename=path.name
        )
    return message


def send(settings: MailSettings, message: EmailMessage) -> None:
    with smtplib.SMTP(settings.host, settings.port, timeout=60) as smtp:
        smtp.ehlo()
        if settings.use_starttls:
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        if settings.auth == "login":
            smtp.login(settings.username, settings.password)
        elif settings.auth == "oauth2":
            token = fetch_access_token(settings)
            code, reply = smtp.docmd("AUTH", "XOAUTH2 " + xoauth2_string(settings.username, token))
            if code != 235:
                raise MailError(f"XOAUTH2 authentication failed: {code} {reply!r}")
        smtp.send_message(message)
    log.info(
        "Mail '%s' sent to %s", message["Subject"], ", ".join(settings.recipients + settings.cc)
    )
