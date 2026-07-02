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
from utils.deduplication import is_seen, is_url_scanned, mark_seen, mark_url_scanned, save as save_hashes
from utils.keywords import KEYWORDS
from utils.patterns import scan_text
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


def scan_spec(url: str) -> list[dict]:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code != 200:
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
        key = (dedup_url, pattern_name)
        if key in seen_in_run:
            continue
        seen_in_run.add(key)
        if use_dedup and is_seen("swaggerhub", dedup_url, pattern_name):
            continue
        if use_dedup:
            mark_seen("swaggerhub", dedup_url, pattern_name)
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

    for keyword in keywords:
        print(f"[SwaggerHub] Scanning: {keyword}")
        all_specs = get_specs(keyword)
        if candidates is not None:
            candidates.extend(_candidate_record(spec) for spec in all_specs)

        new_specs = [
            spec for spec in all_specs
            if not (use_dedup and is_url_scanned("swaggerhub", spec["spec_url"]))
        ]
        skipped = len(all_specs) - len(new_specs)
        if skipped:
            print(f"[SwaggerHub] {keyword}: skipping {skipped} already-scanned, {len(new_specs)} new")

        if not new_specs:
            time.sleep(1)
            continue

        for spec in new_specs:
            _append_hits(
                all_matches,
                seen_in_run,
                spec,
                scan_text(spec.get("metadata_text", "")),
                "search_metadata",
                use_dedup,
                categories,
            )

        with ThreadPoolExecutor(max_workers=10) as ex:
            future_to_spec = {ex.submit(scan_spec, spec["spec_url"]): spec for spec in new_specs}
            for fut in as_completed(future_to_spec):
                spec = future_to_spec[fut]
                hits = fut.result()
                if use_dedup:
                    mark_url_scanned("swaggerhub", spec["spec_url"])
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
            json.dumps(existing + all_matches, indent=2, ensure_ascii=False)
        )
    print(f"[SwaggerHub] Done. {len(all_matches)} new findings.")


if __name__ == "__main__":
    main()
