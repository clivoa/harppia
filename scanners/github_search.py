#!/usr/bin/env python3
"""GitHub Code Search scanner — finds credentials in public repos."""
import base64
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.deduplication import is_seen, mark_seen, save as save_hashes
from utils.keyword_match import keyword_in_text
from utils.keywords import KEYWORDS
from utils.patterns import scan_text
from utils.redaction import reveal_secrets, sanitize_findings
from utils.telegram import send_alert

OUTPUT_DIR = Path("data/github_search")
GH_PAT = os.environ.get("GH_PAT", "")
SEARCH_URL = "https://api.github.com/search/code"
RAW_URL = "https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}"
CONTENT_ACCEPT = "application/vnd.github.v3.raw"

# File types most likely to contain credentials
EXTENSIONS = ["env", "properties", "yml", "yaml", "json", "xml", "cfg", "ini", "conf"]


def _headers(accept: str = "application/vnd.github.v3+json") -> dict:
    pat = os.environ.get("GH_PAT", GH_PAT)
    h = {"Accept": accept, "User-Agent": "harppia/1.0"}
    if pat:
        h["Authorization"] = f"token {pat}"
    return h


def _since_date(hours: int = 24) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d")


def _search_keyword(keyword: str, extension: str, since: str) -> list[dict]:
    query = f'"{keyword}" in:file extension:{extension} pushed:>{since}'
    params = {"q": query, "per_page": 30}
    try:
        resp = requests.get(SEARCH_URL, headers=_headers(), params=params, timeout=30)
        if resp.status_code == 403:
            print("[GitHubSearch] Rate limited. Sleeping 60s...")
            time.sleep(60)
            resp = requests.get(SEARCH_URL, headers=_headers(), params=params, timeout=30)
        if resp.status_code != 200:
            print(f"[GitHubSearch] HTTP {resp.status_code} for '{keyword}' ext:{extension}")
            return []
        return resp.json().get("items", [])
    except Exception as e:
        print(f"[GitHubSearch] Error searching '{keyword}' ext:{extension}: {e}")
        return []


def _raw_url(item: dict) -> str:
    repo = item.get("repository", {})
    owner = repo.get("owner", {}).get("login", "")
    repo_name = repo.get("name", "")
    sha = repo.get("default_branch") or "HEAD"
    path = item.get("path", "")
    return RAW_URL.format(owner=owner, repo=repo_name, sha=sha, path=path)


def _content_key(item: dict) -> str:
    repo = item.get("repository", {})
    full_name = repo.get("full_name", "")
    path = item.get("path", "")
    if full_name and path:
        return f"{full_name}/{path}"
    return item.get("html_url") or item.get("url", "")


def _decode_content_response(resp: requests.Response) -> str:
    content_type = resp.headers.get("Content-Type", "").lower()
    if "json" not in content_type:
        return resp.text

    try:
        data = resp.json()
    except Exception:
        return resp.text

    content = data.get("content", "")
    if data.get("encoding") == "base64" and content:
        compact = "".join(content.split())
        try:
            return base64.b64decode(compact).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return content if isinstance(content, str) else ""


def _fetch_content(item: dict) -> str:
    content_url = item.get("url", "")
    if content_url:
        try:
            resp = requests.get(content_url, headers=_headers(CONTENT_ACCEPT), timeout=30)
            if resp.status_code == 200:
                return _decode_content_response(resp)
            if resp.status_code == 403:
                print("[GitHubSearch] Rate limited while fetching content. Sleeping 60s...")
                time.sleep(60)
        except Exception as e:
            print(f"[GitHubSearch] Error fetching {content_url}: {e}")

    raw_url = _raw_url(item)
    try:
        resp = requests.get(raw_url, headers=_headers(), timeout=30)
        if resp.status_code == 200:
            return resp.text
    except Exception as e:
        print(f"[GitHubSearch] Error fetching {raw_url}: {e}")
    return ""


def scan(keywords: list[str], use_dedup: bool = True, since_hours: int = 24) -> list[dict]:
    """Scan GitHub Code Search for credentials. Core logic shared by main() and the CLI.

    since_hours: how far back to look (default 24h; pass 0 or a large number for no time filter).
    """
    if not os.environ.get("GH_PAT", GH_PAT):
        print("[GitHubSearch] WARNING: GH_PAT not set. Rate limits will be very low.")

    since = _since_date(since_hours) if since_hours > 0 else "2000-01-01"
    print(f"[GitHubSearch] Time window: pushed after {since}")
    all_matches: list[dict] = []

    for keyword in keywords:
        print(f"[GitHubSearch] Scanning: {keyword}")
        seen_item_keys: set[str] = set()

        for ext in EXTENSIONS:
            items = _search_keyword(keyword, ext, since)
            time.sleep(2)  # stay under 30 req/min

            for item in items:
                content_key = _content_key(item)
                raw = _raw_url(item)
                html_url = item.get("html_url", "")

                if content_key in seen_item_keys:
                    continue
                seen_item_keys.add(content_key)

                content = _fetch_content(item)
                if not content:
                    continue
                if not keyword_in_text(content, keyword):
                    continue
                time.sleep(0.5)

                for hit in scan_text(content):
                    pattern_name = hit["pattern_name"]
                    matched_value = hit.get("matched_value", "")
                    if use_dedup and is_seen("github_search", content_key, pattern_name, matched_value):
                        continue
                    if use_dedup:
                        mark_seen("github_search", content_key, pattern_name, matched_value)
                    finding = {
                        "source": "github_search",
                        "keyword": keyword,
                        "url": html_url,
                        "raw_url": raw,
                        "content_url": item.get("url", ""),
                        "extension": ext,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        **hit,
                    }
                    send_alert(finding)
                    all_matches.append(finding)
                    print(f"[GitHubSearch] MATCH: {pattern_name} in {html_url}")

    if use_dedup:
        save_hashes()

    return all_matches


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    all_matches = scan(KEYWORDS, use_dedup=True, since_hours=24)

    if all_matches:
        matches_path = OUTPUT_DIR / f"{date}_matches.json"
        existing: list = []
        if matches_path.exists():
            try:
                existing = json.loads(matches_path.read_text())
            except Exception:
                pass
        matches_path.write_text(
            json.dumps(
                sanitize_findings(existing + all_matches, reveal=reveal_secrets()),
                indent=2,
                ensure_ascii=False,
            )
        )
    print(f"[GitHubSearch] Done. {len(all_matches)} new findings.")


if __name__ == "__main__":
    main()
