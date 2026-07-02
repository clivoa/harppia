#!/usr/bin/env python3
"""GitHub Code Search scanner — finds credentials in public repos."""
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.deduplication import is_seen, mark_seen, save as save_hashes
from utils.keywords import KEYWORDS
from utils.patterns import scan_text
from utils.telegram import send_alert

OUTPUT_DIR = Path("data/github_search")
GH_PAT = os.environ.get("GH_PAT", "")
SEARCH_URL = "https://api.github.com/search/code"
RAW_URL = "https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}"

# File types most likely to contain credentials
EXTENSIONS = ["env", "properties", "yml", "yaml", "json", "xml", "cfg", "ini", "conf"]


def _headers() -> dict:
    pat = os.environ.get("GH_PAT", GH_PAT)
    h = {"Accept": "application/vnd.github.v3+json", "User-Agent": "harppia/1.0"}
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
    sha = item.get("sha", "")
    path = item.get("path", "")
    return RAW_URL.format(owner=owner, repo=repo_name, sha=sha, path=path)


def _fetch_content(raw_url: str) -> str:
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
        seen_item_urls: set[str] = set()

        for ext in EXTENSIONS:
            items = _search_keyword(keyword, ext, since)
            time.sleep(2)  # stay under 30 req/min

            for item in items:
                raw = _raw_url(item)
                html_url = item.get("html_url", "")

                if raw in seen_item_urls:
                    continue
                seen_item_urls.add(raw)

                content = _fetch_content(raw)
                if not content:
                    continue
                time.sleep(0.5)

                for hit in scan_text(content):
                    pattern_name = hit["pattern_name"]
                    if use_dedup and is_seen("github_search", raw, pattern_name):
                        continue
                    if use_dedup:
                        mark_seen("github_search", raw, pattern_name)
                    finding = {
                        "source": "github_search",
                        "keyword": keyword,
                        "url": html_url,
                        "raw_url": raw,
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
            json.dumps(existing + all_matches, indent=2, ensure_ascii=False)
        )
    print(f"[GitHubSearch] Done. {len(all_matches)} new findings.")


if __name__ == "__main__":
    main()
