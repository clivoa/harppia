#!/usr/bin/env python3
"""Aggregates daily findings from all scanners into categorized CSV and JSON reports."""
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path("data")
REPORTS_DIR = Path("reports")
SOURCES = ["swaggerhub", "github_search", "github_gists", "formatters"]
CATEGORIES = ["credential", "token", "pii", "infrastructure"]

CSV_FIELDS = ["timestamp", "source", "keyword", "category", "pattern_name", "matched_value", "url"]


def load_findings(date: str) -> list[dict]:
    all_findings = []
    for source in SOURCES:
        candidates = [
            DATA_DIR / source / f"{date}_matches.json",
            DATA_DIR / f"formatters_{date}_matches.json",
        ]
        for path in candidates:
            if not path.exists():
                continue
            try:
                items = json.loads(path.read_text(encoding="utf-8"))
                all_findings.extend(items)
            except Exception as e:
                print(f"[Compile] Could not read {path}: {e}")
    return all_findings


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    findings = load_findings(date)

    if not findings:
        print(f"[Compile] No findings for {date}.")
        return

    REPORTS_DIR.mkdir(exist_ok=True)

    by_category: dict[str, list[dict]] = {c: [] for c in CATEGORIES}
    for f in findings:
        cat = f.get("category", "credential")
        by_category.setdefault(cat, []).append(f)

    for cat, rows in by_category.items():
        if rows:
            csv_path = REPORTS_DIR / f"{date}_{cat}.csv"
            write_csv(csv_path, rows)
            print(f"[Compile] {csv_path}: {len(rows)} rows")

    summary = {
        "date": date,
        "total": len(findings),
        "by_category": {cat: len(rows) for cat, rows in by_category.items() if rows},
        "by_source": {},
        "by_keyword": {},
        "top_patterns": {},
    }
    for f in findings:
        summary["by_source"][f.get("source", "?")] = summary["by_source"].get(f.get("source", "?"), 0) + 1
        summary["by_keyword"][f.get("keyword", "?")] = summary["by_keyword"].get(f.get("keyword", "?"), 0) + 1
        summary["top_patterns"][f.get("pattern_name", "?")] = summary["top_patterns"].get(f.get("pattern_name", "?"), 0) + 1

    summary["by_keyword"] = dict(sorted(summary["by_keyword"].items(), key=lambda x: -x[1]))
    summary["top_patterns"] = dict(sorted(summary["top_patterns"].items(), key=lambda x: -x[1]))

    summary_path = REPORTS_DIR / f"{date}_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[Compile] {summary_path}: {len(findings)} total findings")


if __name__ == "__main__":
    main()
