#!/usr/bin/env python3
"""npm registry scanner — scans public package metadata and READMEs for credentials."""
import json
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

OUTPUT_DIR = Path("data/npm")
SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
PKG_URL = "https://registry.npmjs.org/{name}"
_UA = "Mozilla/5.0 (compatible; harppia/1.0)"
_HEADERS = {"User-Agent": _UA, "Accept": "application/json"}
# Max packages to fetch full metadata for per keyword (search returns summaries only)
_MAX_FULL_FETCH = 50


def _search(keyword: str, size: int = 250) -> list[dict]:
    try:
        resp = requests.get(
            SEARCH_URL,
            params={"text": keyword, "size": size},
            headers=_HEADERS,
            timeout=20,
        )
        if not resp.ok:
            print(f"[npm] HTTP {resp.status_code} searching '{keyword}'")
            return []
        return resp.json().get("objects", [])
    except Exception as e:
        print(f"[npm] Error searching '{keyword}': {e}")
        return []


def _fetch_package(name: str) -> dict:
    try:
        resp = requests.get(
            PKG_URL.format(name=requests.utils.quote(name, safe="")),
            headers=_HEADERS,
            timeout=20,
        )
        if not resp.ok:
            return {}
        return resp.json()
    except Exception as e:
        print(f"[npm] Error fetching package '{name}': {e}")
        return {}


def _package_text(pkg_data: dict, summary: dict) -> str:
    """Build a single string from all scannable text in a package."""
    parts = [
        pkg_data.get("readme", ""),
        pkg_data.get("description", ""),
        summary.get("package", {}).get("description", ""),
    ]
    # Also scan the latest version's package.json fields that may have credentials
    latest_version = pkg_data.get("dist-tags", {}).get("latest", "")
    version_data = pkg_data.get("versions", {}).get(latest_version, {})
    for field in ("scripts", "config", "_resolved"):
        val = version_data.get(field)
        if val:
            parts.append(json.dumps(val))
    return "\n".join(str(p) for p in parts if p)


def scan(keywords: list[str], use_dedup: bool = True) -> list[dict]:
    """Scan npm registry for credentials. Core logic shared by main() and the CLI."""
    all_findings: list[dict] = []
    fetched_packages: set[str] = set()

    for keyword in keywords:
        print(f"[npm] Scanning: {keyword}")
        results = _search(keyword)
        print(f"[npm] {len(results)} package(s) found for '{keyword}'")

        fetch_count = 0
        for obj in results:
            pkg = obj.get("package", {})
            name = pkg.get("name", "")
            if not name or name in fetched_packages:
                continue

            # Quick filter: keyword must appear in the search-returned summary
            summary_text = " ".join([
                name,
                pkg.get("description", ""),
                " ".join(pkg.get("keywords", [])),
            ])
            if not keyword_in_text(summary_text, keyword):
                continue

            if fetch_count >= _MAX_FULL_FETCH:
                break
            fetched_packages.add(name)
            fetch_count += 1

            pkg_data = _fetch_package(name)
            if not pkg_data:
                continue

            content = _package_text(pkg_data, obj)
            if not keyword_in_text(content, keyword):
                continue

            pkg_url = f"https://www.npmjs.com/package/{name}"
            dedup_key = name

            for hit in scan_text(content):
                pattern_name = hit["pattern_name"]
                matched_value = hit.get("matched_value", "")
                if use_dedup and is_seen("npm", dedup_key, pattern_name, matched_value):
                    continue
                if use_dedup:
                    mark_seen("npm", dedup_key, pattern_name, matched_value)
                finding = {
                    "source": "npm",
                    "keyword": keyword,
                    "url": pkg_url,
                    "package": name,
                    "version": pkg_data.get("dist-tags", {}).get("latest", ""),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **hit,
                }
                send_alert(finding)
                all_findings.append(finding)
                print(f"[npm] MATCH: {pattern_name} in {pkg_url}")

            time.sleep(0.5)

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
    print(f"[npm] Done. {len(all_findings)} credential findings.")


if __name__ == "__main__":
    main()
