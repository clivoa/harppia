#!/usr/bin/env python3
"""SwaggerHub OSINT scanner — searches for credentials in public API specs."""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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

OUTPUT_DIR = Path("data/swaggerhub")
API_URL = "https://app.swaggerhub.com/apiproxy/specs"
HEADERS = {"accept": "application/json", "User-Agent": "harppia/1.0"}

# Only take the first page (top 100 by BEST_MATCH) per keyword.
# This avoids fetching hundreds of cloned/forked documentation specs.
MAX_PAGES = 1


def _prop_value(api: dict, prop_type: str) -> str:
    for prop in api.get("properties", []):
        if prop.get("type") == prop_type:
            return prop.get("url") or prop.get("value") or ""
    return ""


def _ui_url(spec_url: str) -> str:
    prefix = "https://api.swaggerhub.com/apis/"
    if spec_url.startswith(prefix):
        return "https://app.swaggerhub.com/apis/" + spec_url[len(prefix):]
    return spec_url


def _metadata_text(api: dict) -> str:
    values = [api.get("name", ""), api.get("summary", ""), api.get("description", "")]
    for prop in api.get("properties", []):
        values.append(str(prop.get("value", "")))
    return "\n".join(v for v in values if v)


def _parse_specs(data: dict, keyword: str) -> list[dict]:
    specs = []
    for api in data.get("apis", []):
        spec_url = _prop_value(api, "Swagger")
        if not spec_url:
            continue

        specs.append(
            {
                "source": "swaggerhub",
                "keyword": keyword,
                "name": api.get("name", ""),
                "owner": _prop_value(api, "X-Owner"),
                "api_name": _prop_value(api, "X-Name"),
                "version": _prop_value(api, "X-Version"),
                "published": _prop_value(api, "X-Published"),
                "modified": _prop_value(api, "X-Modified"),
                "oas_version": _prop_value(api, "X-OASVersion"),
                "url": _ui_url(spec_url),
                "spec_url": spec_url,
                "metadata_text": _metadata_text(api),
            }
        )
    return specs


def _candidate_record(spec: dict) -> dict:
    return {
        "source": spec["source"],
        "keyword": spec["keyword"],
        "name": spec["name"],
        "owner": spec["owner"],
        "api_name": spec["api_name"],
        "version": spec["version"],
        "published": spec["published"],
        "modified": spec["modified"],
        "oas_version": spec["oas_version"],
        "url": spec["url"],
        "spec_url": spec["spec_url"],
    }


def get_specs(keyword: str) -> list[dict]:
    try:
        resp = requests.get(
            API_URL,
            headers=HEADERS,
            params={
                "sort": "BEST_MATCH",
                "order": "DESC",
                "query": keyword,
                "page": 0,
                "limit": 100,
            },
            timeout=30,
        )
        data = resp.json()
    except Exception as e:
        print(f"[SwaggerHub] Error fetching '{keyword}': {e}")
        return []
    total = int(data.get("totalCount", 0))
    print(f"[SwaggerHub] {keyword}: {total} total specs, scanning top {min(total, 100)}")
    return _parse_specs(data, keyword)


def scan_spec(url: str, keyword: str = "", keyword_confirmed: bool = False) -> list[dict]:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code != 200:
            return []
        if keyword and not keyword_confirmed and not keyword_in_text(resp.text, keyword):
            return []
        return scan_text(resp.text)
    except Exception as e:
        print(f"[SwaggerHub] Error scanning {url}: {e}")
        return []


def _append_hits(
    all_matches: list[dict],
    seen_in_run: set[tuple],
    spec: dict,
    hits: list[dict],
    match_location: str,
    use_dedup: bool,
    categories=None,
) -> None:
    dedup_url = spec["spec_url"]
    for hit in hits:
        if categories and hit.get("category") not in categories:
            continue
        pattern_name = hit["pattern_name"]
        matched_value = hit.get("matched_value", "")
        key = (dedup_url, pattern_name, matched_value)
        if key in seen_in_run:
            continue
        seen_in_run.add(key)
        if use_dedup and is_seen("swaggerhub", dedup_url, pattern_name, matched_value):
            continue
        if use_dedup:
            mark_seen("swaggerhub", dedup_url, pattern_name, matched_value)
        finding = {
            "source": "swaggerhub",
            "keyword": spec["keyword"],
            "url": spec["url"],
            "spec_url": spec["spec_url"],
            "match_location": match_location,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **hit,
        }
        send_alert(finding)
        all_matches.append(finding)
        print(f"[SwaggerHub] MATCH [{hit['category']}]: {pattern_name} in {spec['url']}")


def scan(keywords: list[str], use_dedup: bool = True, candidates=None, categories=None) -> list[dict]:
    """Scan SwaggerHub for credentials. Core logic shared by main() and the CLI."""
    all_matches: list[dict] = []
    seen_in_run: set[tuple] = set()
    scanned_urls_in_run: set[str] = set()

    for keyword in keywords:
        print(f"[SwaggerHub] Scanning: {keyword}")
        all_specs = get_specs(keyword)
        if candidates is not None:
            candidates.extend(_candidate_record(spec) for spec in all_specs)

        new_specs = []
        for spec in all_specs:
            spec_url = spec["spec_url"]
            if spec_url in scanned_urls_in_run:
                continue
            scanned_urls_in_run.add(spec_url)
            new_specs.append(spec)

        skipped = len(all_specs) - len(new_specs)
        if skipped:
            print(f"[SwaggerHub] {keyword}: skipping {skipped} duplicate(s) in this run")

        if not new_specs:
            time.sleep(1)
            continue

        metadata_matches: dict[str, bool] = {}
        for spec in new_specs:
            metadata_matches[spec["spec_url"]] = keyword_in_text(
                spec.get("metadata_text", ""),
                spec["keyword"],
            )
            _append_hits(
                all_matches,
                seen_in_run,
                spec,
                scan_text(spec.get("metadata_text", "")) if metadata_matches[spec["spec_url"]] else [],
                "search_metadata",
                use_dedup,
                categories,
            )

        with ThreadPoolExecutor(max_workers=10) as ex:
            future_to_spec = {
                ex.submit(
                    scan_spec,
                    spec["spec_url"],
                    spec["keyword"],
                    metadata_matches.get(spec["spec_url"], False),
                ): spec
                for spec in new_specs
            }
            for fut in as_completed(future_to_spec):
                spec = future_to_spec[fut]
                hits = fut.result()
                _append_hits(all_matches, seen_in_run, spec, hits, "spec", use_dedup, categories)

        time.sleep(1)

    if use_dedup:
        save_hashes()

    return all_matches


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    all_matches = scan(KEYWORDS, use_dedup=True)

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
    print(f"[SwaggerHub] Done. {len(all_matches)} new findings.")


if __name__ == "__main__":
    main()
