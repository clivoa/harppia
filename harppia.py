#!/usr/bin/env python3
"""
harppia — ad-hoc OSINT credential scanner

Scan public sources for leaked secrets without GitHub Actions.

Examples:
  python harppia.py -k target-name -k target-domain.example
  python harppia.py -k target-name --scanner swaggerhub,github
  python harppia.py -k target-name --output findings.json
  python harppia.py -k target-name --no-dedup --no-alert
  python harppia.py -k target-name --gh-pat ghp_xxx --since-hours 72
"""
import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── ANSI colour codes (disabled automatically when not a TTY) ─────────────────
_COLOUR = sys.stdout.isatty()

_C = {
    "credential":     "\033[91m",   # red
    "token":          "\033[93m",   # yellow
    "pii":            "\033[94m",   # blue
    "infrastructure": "\033[90m",   # dark grey
    "reset":          "\033[0m",
    "bold":           "\033[1m",
    "dim":            "\033[2m",
}

_BANNER = r"""
 _                           _
| |__   __ _ _ __ _ __  _ __ (_) __ _
| '_ \ / _` | '__| '_ \| '_ \| |/ _` |
| | | | (_| | |  | |_) | |_) | | (_| |
|_| |_|\__,_|_|  | .__/| .__/|_|\__,_|
                 |_|   |_|
""".strip("\n")


def _c(key: str, text: str) -> str:
    if not _COLOUR:
        return text
    return f"{_C.get(key, '')}{text}{_C['reset']}"


# ── Terminal output ────────────────────────────────────────────────────────────

def _print_finding(f: dict) -> None:
    cat = f.get("category", "credential")
    label = _c(cat, _c("bold", cat.upper()))
    sep = _c("dim", "─" * 60)
    print(sep)
    print(f"  {label}  {_c('bold', f.get('pattern_name', ''))}")
    print(f"  {'Source':<9}: {f.get('source', '')}")
    print(f"  {'Keyword':<9}: {f.get('keyword', '')}")
    print(f"  {'URL':<9}: {f.get('url', '')}")
    print(f"  {'Match':<9}: {f.get('matched_value', '')}")
    ts = f.get("timestamp", "")[:19].replace("T", " ")
    print(f"  {'Time':<9}: {ts} UTC")


def _print_summary(findings: list[dict]) -> None:
    if not findings:
        print(_c("dim", "\nNo findings."))
        return

    by_cat: dict[str, int] = {}
    by_src: dict[str, int] = {}
    for f in findings:
        cat = f.get("category", "?")
        src = f.get("source", "?")
        by_cat[cat] = by_cat.get(cat, 0) + 1
        by_src[src] = by_src.get(src, 0) + 1

    print(_c("dim", "─" * 60))
    print(_c("bold", f"\n  {len(findings)} finding(s)\n"))
    for cat, n in sorted(by_cat.items()):
        print(f"  {_c(cat, cat):<22} {n}")
    if len(by_src) > 1:
        print()
        for src, n in sorted(by_src.items()):
            print(f"  {src:<22} {n}")
    print()


# ── Output file ───────────────────────────────────────────────────────────────

_CSV_FIELDS = ["timestamp", "source", "keyword", "category", "pattern_name", "matched_value", "url"]
_CATEGORIES = {"credential", "token", "pii", "infrastructure"}


def _save(findings: list[dict], path: str, fmt: str) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "csv":
        with out.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
            w.writeheader()
            w.writerows(findings)
    else:
        out.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Saved {len(findings)} finding(s) to {out}")


def _save_candidates(candidates: list[dict], path: str) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(candidates, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Saved {len(candidates)} candidate(s) to {out}")


def _expand_csv(values) -> list[str]:
    expanded: list[str] = []
    for value in values or []:
        expanded.extend(item.strip().lower() for item in value.split(",") if item.strip())
    return expanded


def _filter_findings(findings: list[dict], categories: list[str]) -> list[dict]:
    if not categories:
        return findings
    category_set = set(categories)
    return [f for f in findings if f.get("category") in category_set]


# ── Runner ────────────────────────────────────────────────────────────────────

def _run(args: argparse.Namespace) -> tuple[list[dict], list[dict]]:
    # Apply env overrides from CLI flags before any scanner import reads os.environ
    if args.gh_pat:
        os.environ["GH_PAT"] = args.gh_pat
    if args.telegram_token:
        os.environ["TELEGRAM_BOT_TOKEN"] = args.telegram_token
    if args.telegram_chat:
        os.environ["TELEGRAM_CHAT_ID"] = args.telegram_chat
    if args.no_alert:
        os.environ.pop("TELEGRAM_BOT_TOKEN", None)
        os.environ.pop("TELEGRAM_CHAT_ID", None)

    # Resolve keywords: CLI flags take precedence, then fall back to keywords.py
    keywords = args.keyword or []
    if not keywords:
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from utils.keywords import KEYWORDS
            keywords = list(KEYWORDS)
        except Exception:
            pass
    if not keywords:
        print("Error: no keywords. Use -k KEYWORD or populate utils/keywords.py", file=sys.stderr)
        sys.exit(1)

    print(_c("bold", f"\n{_BANNER}\n"))
    print(_c("bold", f"harppia — scanning {len(keywords)} keyword(s)\n"))
    for kw in keywords:
        print(f"  · {kw}")
    print()

    scanners = {s.strip().lower() for s in (args.scanner or ["all"])}
    run_all = "all" in scanners
    use_dedup = not args.no_dedup
    all_findings: list[dict] = []
    all_candidates: list[dict] = []
    category_filter = set(args.category) if args.category else None

    if run_all or "swaggerhub" in scanners:
        from scanners.swaggerhub import scan as sw_scan
        candidates = all_candidates if args.candidates_output else None
        all_findings.extend(
            sw_scan(
                keywords,
                use_dedup=use_dedup,
                candidates=candidates,
                categories=category_filter,
            )
        )

    if run_all or "gists" in scanners:
        from scanners.github_gist import scan as gist_scan
        all_findings.extend(gist_scan(keywords, use_dedup=use_dedup, hours=args.gist_hours))

    if run_all or "github" in scanners:
        from scanners.github_search import scan as gh_scan
        all_findings.extend(gh_scan(keywords, use_dedup=use_dedup, since_hours=args.since_hours))

    if run_all or "formatters" in scanners:
        from scanners.formatters import scan as fmt_scan
        all_findings.extend(fmt_scan(keywords, use_dedup=use_dedup))

    return all_findings, all_candidates


# ── Entry point ───────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="harppia",
        description="Ad-hoc OSINT credential scanner — no GitHub Actions required.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
scanners: swaggerhub, github, gists, formatters, all (default: all)

examples:
  python harppia.py -k target-name -k target-domain.example
  python harppia.py -k target-name --scanner swaggerhub,gists
  python harppia.py -k target-name --no-dedup --output findings.json
  python harppia.py -k target-name --gh-pat ghp_xxx --since-hours 72
        """,
    )

    p.add_argument(
        "-k", "--keyword",
        action="append",
        metavar="KEYWORD",
        help="Keyword to scan (repeat for multiple). Defaults to utils/keywords.py if omitted.",
    )
    p.add_argument(
        "-s", "--scanner",
        action="append",
        metavar="SCANNER",
        help="Scanners to run: swaggerhub, github, gists, formatters, all (default: all). "
             "Comma-separated or repeat the flag.",
    )
    p.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save findings to FILE (JSON by default, CSV with --format csv).",
    )
    p.add_argument(
        "--candidates-output",
        metavar="FILE",
        help="Save discovered candidate URLs/metadata to FILE (SwaggerHub currently).",
    )
    p.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output file format (default: json).",
    )
    p.add_argument(
        "--category",
        action="append",
        metavar="CATEGORY",
        help="Only print/save findings from category: credential, token, pii, infrastructure. "
             "Comma-separated or repeat the flag.",
    )
    p.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable cross-run deduplication — scan everything fresh.",
    )
    p.add_argument(
        "--no-alert",
        action="store_true",
        help="Suppress Telegram alerts for this run.",
    )
    p.add_argument(
        "--gh-pat",
        metavar="TOKEN",
        default=os.environ.get("GH_PAT", ""),
        help="GitHub PAT (overrides GH_PAT env var).",
    )
    p.add_argument(
        "--telegram-token",
        metavar="TOKEN",
        help="Telegram bot token (overrides TELEGRAM_BOT_TOKEN env var).",
    )
    p.add_argument(
        "--telegram-chat",
        metavar="CHAT_ID",
        help="Telegram chat/channel ID (overrides TELEGRAM_CHAT_ID env var).",
    )
    p.add_argument(
        "--since-hours",
        type=int,
        default=24,
        metavar="N",
        help="GitHub Code Search: look back N hours (default: 24). Use 0 for no time filter.",
    )
    p.add_argument(
        "--gist-hours",
        type=int,
        default=6,
        metavar="N",
        help="Gist timeline: scan gists updated in the last N hours (default: 6). Use 0 to skip timeline.",
    )

    return p


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # Allow comma-separated scanners: --scanner swaggerhub,github
    if args.scanner:
        args.scanner = _expand_csv(args.scanner)
    args.category = _expand_csv(args.category)
    invalid_categories = sorted(set(args.category) - _CATEGORIES)
    if invalid_categories:
        parser.error(f"invalid category: {', '.join(invalid_categories)}")

    findings, candidates = _run(args)
    findings = _filter_findings(findings, args.category)

    for f in findings:
        _print_finding(f)

    _print_summary(findings)

    if args.output:
        _save(findings, args.output, args.format)
    if args.candidates_output:
        _save_candidates(candidates, args.candidates_output)


if __name__ == "__main__":
    main()
