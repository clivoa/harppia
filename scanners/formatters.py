#!/usr/bin/env python3
"""JSON/YAML formatter site scanner — scans recent paste links for credentials."""
import ctypes
import json
import re
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

OUTPUT_DIR = Path("data")

# Full browser UA required — jsonformatter.org rejects bot-like strings
_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_JF_SECRET = "JF_SECURE_V4_8f3e2b9a"
_CONTENT_API = "https://jsonformatter.org/service/getDataFromID"

# /json is blocked by Cloudflare Managed Challenge; /yaml and /xml are accessible.
# codebeautify.org also returns 403.
ENDPOINTS = [
    "https://jsonformatter.org/recentLinksPage/yaml",
    "https://jsonformatter.org/recentLinksPage/xml",
]


def _jf_hash(s: str) -> str:
    """Reimplementation of the site's _sh() JS function (djb2-style, 32-bit)."""
    t = 0
    for c in s:
        t = ctypes.c_int32((t << 5) - t + ord(c)).value
    return format(ctypes.c_uint32(t).value, "x")


def _jf_sig() -> str:
    """Reimplementation of the site's _gs() JS function — rotates every 10 min."""
    bucket = int(time.time() * 1000) // 600000
    return _jf_hash(_JF_SECRET + _USER_AGENT + str(bucket))


def _toolstype(url: str) -> str:
    """Infer toolstype from the formatter page URL path."""
    path = url.split("jsonformatter.org/", 1)[-1].split("/")[0] if "jsonformatter.org/" in url else ""
    if "yaml" in path:
        return "yaml"
    if "xml" in path:
        return "xml"
    return "json"


def _get_first(item: dict, *keys):
    for key in keys:
        for cand in (key, key.lower(), key.upper(), key.capitalize()):
            if cand in item:
                return item[cand]
    return None


def _normalize(item: dict, source: str) -> dict:
    title = _get_first(item, "title", "name", "fileTitle", "text")
    link_id = _get_first(item, "id", "Id", "ID", "linkId", "link_id", "uid")
    date = _get_first(item, "date", "createdDate", "CreatedDate", "created_at", "createdAt", "time", "timestamp")
    url = _get_first(item, "url", "link", "href", "path")
    if not link_id and url and "/" in str(url):
        link_id = str(url).rstrip("/").rsplit("/", 1)[-1]
    return {"source": source, "id": link_id, "title": title, "date": date, "url": url}


def _parse_json_items(data) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "items", "links", "recentLinks", "result"):
            if key in data and isinstance(data[key], list):
                return data[key]
        if data and all(isinstance(v, dict) for v in data.values()):
            return list(data.values())
        return [data]
    return []


def _parse_html_items(html: str, source: str) -> list:
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text)
    items = []
    for part in text.split("Title :")[1:]:
        part = part.strip()
        if not part:
            continue
        split_link = re.split(r"Link\s*:", part, maxsplit=1)
        title_raw = split_link[0].strip()
        m = re.match(r"(.+?)\(\s*([^)]+?)\s*\)\s*$", title_raw)
        title = m.group(1).strip() if m else title_raw
        date = m.group(2).strip() if m else None
        url = None
        if len(split_link) > 1:
            m_url = re.search(r"https?://\S+", split_link[1])
            if m_url:
                url = m_url.group(0).strip().rstrip(")")
        item = {"title": title or None, "url": url, "date": date, "source": source}
        if url and "/" in url:
            item["id"] = url.rstrip("/").rsplit("/", 1)[-1]
        items.append(item)
    return items


def _fetch_and_parse(url: str) -> list:
    print(f"[Formatters] Fetching: {url}")
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": _USER_AGENT})
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else "N/A"
        print(f"[Formatters] HTTP {status} from {url}")
        return []
    except Exception as e:
        print(f"[Formatters] Error fetching {url}: {e}")
        return []

    if "json" in resp.headers.get("Content-Type", "").lower():
        try:
            items = _parse_json_items(resp.json())
            print(f"[Formatters] (JSON) {len(items)} items")
            return items
        except Exception:
            pass

    items = _parse_html_items(resp.text, source=url)
    print(f"[Formatters] (HTML) {len(items)} items")
    return items


def _fetch_raw_content(hash_id: str, content_url: str) -> str:
    """Fetch the raw paste content via the site's internal API."""
    ttype = _toolstype(content_url)
    try:
        resp = requests.post(
            _CONTENT_API,
            headers={
                "User-Agent": _USER_AGENT,
                "Referer": content_url,
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
            },
            data=f"urlid={hash_id}&toolstype={ttype}&sig={_jf_sig()}",
            timeout=20,
        )
        if resp.status_code == 429:
            print("[Formatters] Rate limited on content API, sleeping 15s...")
            time.sleep(15)
            return ""
        if not resp.ok:
            return ""
        data = resp.json()
        if isinstance(data, dict):
            return data.get("content", "")
        return ""
    except Exception as e:
        print(f"[Formatters] Error fetching content {hash_id}: {e}")
        return ""


def scan(keywords: list[str], use_dedup: bool = True) -> list[dict]:
    """Scan formatter paste sites for credentials. Core logic shared by main() and the CLI."""
    all_findings: list[dict] = []

    for idx, endpoint_url in enumerate(ENDPOINTS, start=1):
        if idx > 1:
            time.sleep(3)

        raw_items = _fetch_and_parse(endpoint_url)
        for raw_item in raw_items:
            rec = _normalize(raw_item, source=endpoint_url)
            hash_id = rec.get("id")
            content_url = rec.get("url")
            if not hash_id or not content_url:
                continue

            time.sleep(1)
            content = _fetch_raw_content(hash_id, content_url)
            if not content:
                continue

            matched_kw = find_keyword(content, keywords)
            if matched_kw is None:
                continue

            for hit in scan_text(content):
                pattern_name = hit["pattern_name"]
                matched_value = hit.get("matched_value", "")
                if use_dedup and is_seen("formatters", content_url, pattern_name, matched_value):
                    continue
                if use_dedup:
                    mark_seen("formatters", content_url, pattern_name, matched_value)
                finding = {
                    "source": "formatters",
                    "keyword": matched_kw,
                    "url": content_url,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **hit,
                }
                send_alert(finding)
                all_findings.append(finding)
                print(f"[Formatters] MATCH: {pattern_name} in {content_url}")

    if use_dedup:
        save_hashes()

    return all_findings


def main() -> None:
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    OUTPUT_DIR.mkdir(exist_ok=True)

    all_findings = scan(KEYWORDS, use_dedup=True)

    if all_findings:
        matches_path = OUTPUT_DIR / f"formatters_{date}_matches.json"
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
    print(f"[Formatters] Done. {len(all_findings)} credential findings.")


if __name__ == "__main__":
    main()
