import re
from typing import Optional


def keyword_pattern(keyword: str) -> re.Pattern:
    escaped = re.escape(keyword.strip())
    if "." in keyword:
        return re.compile(rf"(?<![A-Za-z0-9-]){escaped}(?![A-Za-z0-9.-])", re.IGNORECASE)
    return re.compile(rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])", re.IGNORECASE)


def keyword_in_text(text: object, keyword: str) -> bool:
    if not keyword:
        return False
    return bool(keyword_pattern(keyword).search(str(text)))


def find_keyword(text: object, keywords: list[str]) -> Optional[str]:
    for keyword in keywords:
        if keyword_in_text(text, keyword):
            return keyword
    return None
