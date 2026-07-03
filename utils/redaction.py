import hashlib
import os


_TRUTHY = {"1", "true", "yes", "on"}


def reveal_secrets() -> bool:
    return os.environ.get("HARPPIA_SHOW_SECRETS", "").strip().lower() in _TRUTHY


def value_fingerprint(value: object) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def redact_value(value: object) -> str:
    text = str(value)
    if not text:
        return ""

    compact = text.replace("\r", "\\r").replace("\n", "\\n")
    length = len(compact)
    if length <= 4:
        return "*" * length
    if length <= 12:
        return f"{compact[:2]}...{compact[-2:]} ({length} chars)"
    return f"{compact[:4]}...{compact[-4:]} ({length} chars)"


def sanitize_finding(finding: dict, reveal: bool = False) -> dict:
    sanitized = dict(finding)
    value = sanitized.get("matched_value")
    if reveal or value in (None, ""):
        return sanitized
    if sanitized.get("matched_value_hash"):
        return sanitized

    sanitized["matched_value_hash"] = value_fingerprint(value)
    sanitized["matched_value"] = redact_value(value)
    return sanitized


def sanitize_findings(findings: list[dict], reveal: bool = False) -> list[dict]:
    return [sanitize_finding(finding, reveal=reveal) for finding in findings]
