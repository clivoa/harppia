import hashlib
import json
from pathlib import Path

_HASHES_FILE = Path("seen_hashes.json")
_seen: set[str] = set()
_loaded = False


def _load() -> None:
    global _loaded
    if _loaded:
        return
    if _HASHES_FILE.exists():
        try:
            data = json.loads(_HASHES_FILE.read_text(encoding="utf-8"))
            _seen.update(data.get("hashes", []))
        except Exception as e:
            print(f"[Dedup] Could not load {_HASHES_FILE}: {e}")
    _loaded = True


def _make_hash(source: str, url: str, pattern_name: str, matched_value: object = "") -> str:
    normalized_url = _normalize_url(url)
    key = f"{source}|{normalized_url}|{pattern_name}|{matched_value}"
    return hashlib.sha256(key.encode()).hexdigest()


def _normalize_url(url: str) -> str:
    # raw.githubusercontent.com/USER/REPO/COMMIT/path -> USER/REPO/path
    if "raw.githubusercontent.com" in url:
        parts = url.split("/")
        try:
            idx = parts.index("raw.githubusercontent.com")
            user = parts[idx + 1]
            repo = parts[idx + 2]
            path = "/".join(parts[idx + 4:])
            return f"{user}/{repo}/{path}"
        except (ValueError, IndexError):
            pass
    return url


def is_seen(source: str, url: str, pattern_name: str, matched_value: object = "") -> bool:
    _load()
    return _make_hash(source, url, pattern_name, matched_value) in _seen


def mark_seen(source: str, url: str, pattern_name: str, matched_value: object = "") -> None:
    _load()
    _seen.add(_make_hash(source, url, pattern_name, matched_value))


def is_url_scanned(source: str, url: str) -> bool:
    """True if this URL was fully processed in a previous run — skip fetching entirely."""
    _load()
    return _make_hash(source, url, "__SCANNED__") in _seen


def mark_url_scanned(source: str, url: str) -> None:
    _load()
    _seen.add(_make_hash(source, url, "__SCANNED__"))


def save() -> None:
    """Persist all seen hashes to disk. Call once at end of each scanner run."""
    _load()
    _HASHES_FILE.write_text(
        json.dumps({"hashes": sorted(_seen)}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[Dedup] Saved {len(_seen)} hashes to {_HASHES_FILE}")
