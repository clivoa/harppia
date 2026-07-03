# Contributing

Thanks for helping improve Harppia.

## Development Setup

```bash
python3 -m pip install -r requirements.txt
python3 -m py_compile harppia.py compile.py scanners/*.py utils/*.py tests/*.py
python3 -m unittest discover -s tests
```

## Pull Request Checklist

- Keep changes focused and avoid committing scanner output from real runs.
- Add or update tests for detection patterns, keyword matching, redaction, deduplication, or report behavior.
- Keep public examples generic. Do not include real organization secrets, internal URLs, tokens, or raw findings.
- Preserve redaction defaults. Features that reveal raw matched values should require explicit opt-in.

## Adding Detection Patterns

Update both `PATTERNS` and `PATTERN_CATEGORY` in `utils/patterns.py`. The module asserts that both dictionaries stay in sync.

Prefer high-signal, context-aware regexes. When a new pattern can be noisy, add false-positive guards and tests before broadening alerting behavior.
