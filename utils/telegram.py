"""Telegram alert helper — fires only for category=credential findings."""
import os
from html import escape

import requests

from utils.redaction import redact_value

_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
_API_URL = "https://api.telegram.org/bot{token}/sendMessage"


def send_alert(finding: dict) -> None:
    """Send a Telegram message for credential-category findings only."""
    if finding.get("category") != "credential":
        return
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", _BOT_TOKEN)
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", _CHAT_ID)
    if not bot_token or not chat_id:
        return

    source = escape(str(finding.get("source", "unknown")).replace("_", " ").title())
    keyword = escape(str(finding.get("keyword", "")))
    pattern = escape(str(finding.get("pattern_name", "")))
    url = escape(str(finding.get("url", "")))
    match = escape(redact_value(finding.get("matched_value", "")))
    timestamp = escape(str(finding.get("timestamp", "")[:19].replace("T", " ")))

    text = (
        f"<b>CREDENTIAL DETECTED</b>\n\n"
        f"<b>Source:</b> {source}\n"
        f"<b>Keyword:</b> <code>{keyword}</code>\n"
        f"<b>Type:</b> {pattern}\n"
        f"<b>URL:</b> {url}\n"
        f"<b>Match:</b> <code>{match}</code>\n"
        f"<b>Time:</b> {timestamp} UTC"
    )

    try:
        resp = requests.post(
            _API_URL.format(token=bot_token),
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=15,
        )
        if not resp.ok:
            print(f"[Telegram] Warning: {resp.status_code} {resp.text[:200]}")
    except Exception as e:
        print(f"[Telegram] Failed to send alert: {e}")
