#!/usr/bin/env python3
"""Sourcegraph scanner — searches public code across GitHub, GitLab, Bitbucket, and more."""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.deduplication import is_seen, mark_seen, save as save_hashes
from utils.keyword_match import keyword_in_text
from utils.keywords import KEYWORDS
from utils.patterns import scan_text
from utils.redaction import reveal_secrets, sanitize_findings
from utils.telegram import send_alert

OUTPUT_DIR = Path("data/sourcegraph")
STREAM_URL = "https://sourcegraph.com/.api/search/stream"
RAW_URL = "https://sourcegraph.com/{repository}/-/raw/{path}"

# Optional: set SOURCEGRAPH_TOKEN for higher rate limits
_TOKEN = os.environ.get("SOURCEGRAPH_TOKEN", "")
_UA = "Mozilla/5.0 (compatible; harppia/1.0)"

# Max file size to fetch (bytes) — avoids pulling huge generated files
_MAX_FILE_SIZE = 200_000
# Results per keyword query
_COUNT = 50


def _headers() -> dict:
    h = {"User-Agent": _UA, "Accept": "text/event-stream"}
    if _TOKEN:
        h["Authorization"] = f"token {_TOKEN}"
    return h


def _raw_headers() -> dict:
    h = {"User-Agent": _UA}
    if _TOKEN:
        h["Authorization"] = f"token {_TOKEN}"
    return h


def _stream_matches(keyword: str) -> list[dict]:
    """Return content-type file matches from Sourcegraph SSE stream for a keyword."""
    params = {
        "q": f'"{keyword}" type:file count:{_COUNT}',
        "v": "V2",
        "display": _COUNT,
    }
    matches = []
    try:
        resp = requests.get(
            STREAM_URL,
            params=params,
            headers=_headers(),
            timeout=60,
            stream=True,
        )
        if resp.status_code == 429:
            print("[Sourcegraph] Rate limited. Sleeping 60s...")
            time.sleep(60)
            return []
        if not resp.ok:
            print(f"[Sourcegraph] HTTP {resp.status_code} for '{keyword}'")
            return []

        event_type = None
        for line in resp.iter_lines(decode_unicode=True):
            if line.startswith("event:"):
                event_type = line[6:].strip()
            elif line.startswith("data:") and event_type == "matches":
                try:
                    items = json.loads(line[5:])
                    for item in items:
                        if item.get("type") == "content":
                            matches.append(item)
                except Exception:
                    pass
            elif event_type == "done":
                break
    except requests.exceptions.Timeout:
        print(f"[Sourcegraph] Timeout streaming '{keyword}'")
    except Exception as e:
        print(f"[Sourcegraph] Error streaming '{keyword}': {e}")

    return matches


def _fetch_file(repository: str, path: str, rev: str = "HEAD") -> str:
    url = RAW_URL.format(repository=repository, path=path)
    try:
        resp = requests.get(
            url,
            headers=_raw_headers(),
            params={"rev": rev},
            timeout=20,
            stream=True,
        )
        if not resp.ok:
            return ""
        # Read up to _MAX_FILE_SIZE bytes
        content = b""
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) >= _MAX_FILE_SIZE:
                break
        return content.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[Sourcegraph] Error fetching {url}: {e}")
        return ""


def scan(keywords: list[str], use_dedup: bool = True) -> list[dict]:
    """Scan Sourcegraph for credentials. Core logic shared by main() and the CLI."""
    all_findings: list[dict] = []
    scanned_urls_in_run: set[str] = set()

    for keyword in keywords:
        print(f"[Sourcegraph] Scanning: {keyword}")
        matches = _stream_matches(keyword)
        print(f"[Sourcegraph] {len(matches)} file match(es) for '{keyword}'")

        for match in matches:
            repository = match.get("repository", "")
            path = match.get("path", "")
            branches = match.get("branches", ["HEAD"])
            rev = branches[0] if branches else "HEAD"
            file_url = f"https://sourcegraph.com/{repository}/-/blob/{path}"
            dedup_key = f"{repository}/{path}"

            if dedup_key in scanned_urls_in_run:
                continue
            scanned_urls_in_run.add(dedup_key)

            content = _fetch_file(repository, path, rev)
            if not content:
                continue
            if not keyword_in_text(content, keyword):
                continue

            time.sleep(0.3)

            for hit in scan_text(content):
                pattern_name = hit["pattern_name"]
                matched_value = hit.get("matched_value", "")
                if use_dedup and is_seen("sourcegraph", dedup_key, pattern_name, matched_value):
                    continue
                if use_dedup:
                    mark_seen("sourcegraph", dedup_key, pattern_name, matched_value)
                finding = {
                    "source": "sourcegraph",
                    "keyword": keyword,
                    "url": file_url,
                    "repository": repository,
                    "path": path,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **hit,
                }
                send_alert(finding)
                all_findings.append(finding)
                print(f"[Sourcegraph] MATCH: {pattern_name} in {file_url}")

        time.sleep(2)

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
    print(f"[Sourcegraph] Done. {len(all_findings)} credential findings.")


if __name__ == "__main__":
    main()
