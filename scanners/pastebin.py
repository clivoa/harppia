#!/usr/bin/env python3
"""Pastebin scanner — scans recent public pastes for credentials via the Scraping API."""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.deduplication import is_seen, mark_seen, save as save_hashes
from utils.keyword_match import find_keyword
from utils.keywords import KEYWORDS
from utils.patterns import scan_text
from utils.redaction import reveal_secrets, sanitize_findings
from utils.telegram import send_alert

OUTPUT_DIR = Path("data/pastebin")

# Scraping API — requires IP whitelisted via a Pastebin Pro account.
# Whitelist your runner IP at: https://pastebin.com/doc_scraping_api
SCRAPE_LIST_URL = "https://scrape.pastebin.com/api_scraping.php"
SCRAPE_ITEM_URL = "https://scrape.pastebin.com/api_scrape_item.php"

_API_KEY = os.environ.get("PASTEBIN_API_KEY", "")
_UA = "Mozilla/5.0 (compatible; harppia/1.0)"
_HEADERS = {"User-Agent": _UA}
# Number of recent pastes to pull per run (Pastebin max is 250)
_LIMIT = 250
# Delay between content fetches to respect rate limits
_ITEM_DELAY = 0.5


def _list_recent() -> list[dict]:
    """Return recent public pastes. Returns [] if IP is not whitelisted."""
    params: dict = {"limit": _LIMIT}
    try:
        resp = requests.get(SCRAPE_LIST_URL, params=params, headers=_HEADERS, timeout=20)
        if resp.status_code == 403:
            print(
                "[Pastebin] 403: IP not whitelisted for Scraping API.\n"
                "  → Whitelist your runner IP at https://pastebin.com/doc_scraping_api"
            )
            return []
        if not resp.ok:
            print(f"[Pastebin] HTTP {resp.status_code} fetching paste list")
            return []
        return resp.json()
    except Exception as e:
        print(f"[Pastebin] Error fetching paste list: {e}")
        return []


def _fetch_content(paste_key: str) -> str:
    try:
        resp = requests.get(
            SCRAPE_ITEM_URL,
            params={"i": paste_key},
            headers=_HEADERS,
            timeout=20,
        )
        if resp.status_code == 429:
            print("[Pastebin] Rate limited on content fetch, sleeping 30s...")
            time.sleep(30)
            return ""
        if not resp.ok:
            return ""
        return resp.text
    except Exception as e:
        print(f"[Pastebin] Error fetching paste {paste_key}: {e}")
        return ""


def scan(keywords: list[str], use_dedup: bool = True) -> list[dict]:
    """Scan recent Pastebin pastes for credentials. Core logic shared by main() and the CLI."""
    if not _API_KEY:
        print("[Pastebin] WARNING: PASTEBIN_API_KEY not set.")

    all_findings: list[dict] = []

    pastes = _list_recent()
    print(f"[Pastebin] {len(pastes)} recent paste(s) to scan")

    for paste in pastes:
        paste_key = paste.get("key", "")
        paste_url = paste.get("full_url", f"https://pastebin.com/{paste_key}")
        paste_title = paste.get("title", "")
        paste_syntax = paste.get("syntax", "")

        if not paste_key:
            continue

        # Skip binary-heavy syntaxes unlikely to contain text credentials
        if paste_syntax in ("diff", "bash", "hex"):
            pass  # still scan these

        content = _fetch_content(paste_key)
        if not content:
            time.sleep(_ITEM_DELAY)
            continue

        matched_kw = find_keyword(content, keywords)
        if matched_kw is None:
            time.sleep(_ITEM_DELAY)
            continue

        for hit in scan_text(content):
            pattern_name = hit["pattern_name"]
            matched_value = hit.get("matched_value", "")
            if use_dedup and is_seen("pastebin", paste_key, pattern_name, matched_value):
                continue
            if use_dedup:
                mark_seen("pastebin", paste_key, pattern_name, matched_value)
            finding = {
                "source": "pastebin",
                "keyword": matched_kw,
                "url": paste_url,
                "paste_key": paste_key,
                "title": paste_title,
                "syntax": paste_syntax,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **hit,
            }
            send_alert(finding)
            all_findings.append(finding)
            print(f"[Pastebin] MATCH: {pattern_name} in {paste_url}")

        time.sleep(_ITEM_DELAY)

    if use_dedup:
        save_hashes()

    return all_findings


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    all_findings = scan(KEYWORDS, use_dedup=True)

    if all_findings:
        matches_path = OUTPUT_DIR / f"{date}_matches.json"
        existing: list = []
        if matches_path.exists():
            try:
                existing = json.loads(matches_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        matches_path.write_text(
            json.dumps(
                sanitize_findings(existing + all_findings, reveal=reveal_secrets()),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    print(f"[Pastebin] Done. {len(all_findings)} credential findings.")


if __name__ == "__main__":
    main()
