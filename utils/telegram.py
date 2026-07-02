"""Telegram alert helper — fires only for category=credential findings."""
import os

import requests

_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
_API_URL = "https://api.telegram.org/bot{token}/sendMessage"


def send_alert(finding: dict) -> None:
    """Send a Telegram message for credential-category findings only."""
    if finding.get("category") != "credential":
        return
    if not _BOT_TOKEN or not _CHAT_ID:
        return

    source = finding.get("source", "unknown").replace("_", " ").title()
    keyword = finding.get("keyword", "—")
    pattern = finding.get("pattern_name", "—")
    url = finding.get("url", "—")
    match = finding.get("matched_value", "")
    timestamp = finding.get("timestamp", "")[:19].replace("T", " ")

    text = (
        f"CREDENTIAL FOUND\n"
        f"Source: {source}\n"
        f"Keyword: {keyword}\n"
        f"Pattern: {pattern}\n"
        f"URL: {url}\n"
        f"Match: {match}\n"
        f"Time: {timestamp} UTC"
    )

    try:
        requests.post(
            _API_URL.format(token=_BOT_TOKEN),
            json={
                "chat_id": _CHAT_ID,
                "text": text,
                "disable_web_page_preview": True,
            },
            timeout=10,
        )
    except Exception as e:
        print(f"[Telegram] Failed to send alert: {e}")
