#!/usr/bin/env python3
"""GitHub Gist scanner — scans recent public gists for credentials."""
from __future__ import annotations
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.deduplication import is_seen, mark_seen, save as save_hashes
from utils.keyword_match import find_keyword
from utils.keywords import KEYWORDS
from utils.patterns import scan_text
from utils.redaction import reveal_secrets, sanitize_findings
from utils.telegram import send_alert

OUTPUT_DIR = Path("data/github_gists")
GH_PAT = os.environ.get("GH_PAT", "")
GISTS_PUBLIC_URL = "https://api.github.com/gists/public"
GIST_SEARCH_URL = "https://api.github.com/search/code"

# Pages of public gist timeline to scan on each run (only gists updated in last 6h)
TIMELINE_PAGES = 3


def _headers() -> dict:
    pat = os.environ.get("GH_PAT", GH_PAT)
    h = {"Accept": "application/vnd.github.v3+json", "User-Agent": "harppia/1.0"}
    if pat:
        h["Authorization"] = f"token {pat}"
    return h


def _scan_gist(
    gist: dict,
    keywords: list[str],
    use_dedup: bool,
    scanned_urls_in_run: set[str],
) -> list[dict]:
    findings = []
    gist_id = gist.get("id", "")
    gist_url = gist.get("html_url", "")

    for filename, file_info in gist.get("files", {}).items():
        raw_url = file_info.get("raw_url", "")
        if not raw_url:
            continue

        kw = find_keyword(filename, keywords) or find_keyword(gist.get("description", "") or "", keywords)

        if raw_url in scanned_urls_in_run:
            continue
        scanned_urls_in_run.add(raw_url)

        try:
            resp = requests.get(raw_url, headers=_headers(), timeout=30)
            if resp.status_code != 200:
                continue
            content = resp.text
            time.sleep(0.3)
        except Exception as e:
            print(f"[GistScanner] Error fetching {raw_url}: {e}")
            continue

        if kw is None:
            kw = find_keyword(content, keywords)
        if kw is None:
            continue

        for hit in scan_text(content):
            pattern_name = hit["pattern_name"]
            matched_value = hit.get("matched_value", "")
            if use_dedup and is_seen("github_gist", raw_url, pattern_name, matched_value):
                continue
            if use_dedup:
                mark_seen("github_gist", raw_url, pattern_name, matched_value)
            findings.append(
                {
                    "source": "github_gist",
                    "keyword": kw,
                    "gist_id": gist_id,
                    "filename": filename,
                    "url": gist_url,
                    "raw_url": raw_url,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **hit,
                }
            )

    return findings


def _timeline(keywords: list[str], use_dedup: bool, hours: int) -> list[dict]:
    all_findings: list[dict] = []
    scanned_urls_in_run: set[str] = set()
    since_iso = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[GistScanner] Timeline window: since {since_iso}")

    for page in range(1, TIMELINE_PAGES + 1):
        print(f"[GistScanner] Fetching public gist timeline page {page}...")
        try:
            resp = requests.get(
                GISTS_PUBLIC_URL,
                headers=_headers(),
                params={"per_page": 100, "page": page, "since": since_iso},
                timeout=30,
            )
            if resp.status_code == 403:
                print("[GistScanner] Rate limited. Sleeping 60s...")
                time.sleep(60)
                continue
            if resp.status_code != 200:
                print(f"[GistScanner] HTTP {resp.status_code} on page {page}")
                break
            gists = resp.json()
        except Exception as e:
            print(f"[GistScanner] Error on page {page}: {e}")
            break

        print(f"[GistScanner] Page {page}: {len(gists)} gists")
        for gist in gists:
            findings = _scan_gist(gist, keywords, use_dedup, scanned_urls_in_run)
            for f in findings:
                send_alert(f)
                print(f"[GistScanner] MATCH: {f['pattern_name']} in gist {f['gist_id']}")
            all_findings.extend(findings)

        time.sleep(2)

    return all_findings


def _keyword_search(keywords: list[str], use_dedup: bool) -> list[dict]:
    all_findings: list[dict] = []

    for keyword in keywords:
        print(f"[GistScanner] Code-searching gists for: {keyword}")
        try:
            resp = requests.get(
                GIST_SEARCH_URL,
                headers=_headers(),
                params={"q": f'"{keyword}" in:file', "per_page": 30},
                timeout=30,
            )
            if resp.status_code == 403:
                print("[GistScanner] Rate limited. Sleeping 60s...")
                time.sleep(60)
                continue
            if resp.status_code != 200:
                print(f"[GistScanner] Search HTTP {resp.status_code} for '{keyword}'")
                time.sleep(2)
                continue
            items = resp.json().get("items", [])
        except Exception as e:
            print(f"[GistScanner] Error searching '{keyword}': {e}")
            time.sleep(2)
            continue

        for item in items:
            html_url = item.get("html_url", "")
            if "gist.github.com" not in html_url:
                continue

            raw_url = item.get("url", "")
            try:
                resp = requests.get(raw_url, headers=_headers(), timeout=30)
                if resp.status_code != 200:
                    continue
                content = resp.text
                time.sleep(0.5)
            except Exception as e:
                print(f"[GistScanner] Error fetching gist content: {e}")
                continue

            for hit in scan_text(content):
                pattern_name = hit["pattern_name"]
                matched_value = hit.get("matched_value", "")
                if use_dedup and is_seen("github_gist", raw_url, pattern_name, matched_value):
                    continue
                if use_dedup:
                    mark_seen("github_gist", raw_url, pattern_name, matched_value)
                finding = {
                    "source": "github_gist",
                    "keyword": keyword,
                    "url": html_url,
                    "raw_url": raw_url,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **hit,
                }
                send_alert(finding)
                all_findings.append(finding)
                print(f"[GistScanner] MATCH: {pattern_name} in {html_url}")

        time.sleep(3)

    return all_findings


def scan(keywords: list[str], use_dedup: bool = True, hours: int = 6) -> list[dict]:
    """Scan GitHub Gists for credentials. Core logic shared by main() and the CLI.

    hours: timeline window to scan (default 6h for scheduled runs; use 0 to skip timeline).
    """
    if not os.environ.get("GH_PAT", GH_PAT):
        print("[GistScanner] WARNING: GH_PAT not set. Rate limits will be very low.")

    findings = []
    if hours > 0:
        findings.extend(_timeline(keywords, use_dedup, hours))
    findings.extend(_keyword_search(keywords, use_dedup))

    if use_dedup:
        save_hashes()

    return findings


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    all_matches = scan(KEYWORDS, use_dedup=True, hours=6)

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
    print(f"[GistScanner] Done. {len(all_matches)} new findings.")


if __name__ == "__main__":
    main()
