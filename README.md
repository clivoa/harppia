# harppia

<p align="center">
  <img src="harppia.png" alt="harppia" width="640">
</p>

OSINT credential scanner — monitors public sources for leaked secrets matching your keywords.

Harppia scans four surfaces (SwaggerHub API specs, GitHub code search, public Gists, and JSON/YAML formatter paste sites) looking for API keys, tokens, passwords, and other secrets associated with the organizations, brands, domains, or identifiers you define. It runs either **on demand from the command line** or **automatically via GitHub Actions** every 6 hours.

Findings are categorized by signal strength. Only high-confidence credentials trigger a Telegram alert — noisier categories (bearer tokens, JWTs, IP addresses) are logged to CSV for offline review.

---

## Responsible use

Use Harppia only on assets, brands, domains, and organizations you are authorized to monitor. If you use this project to monitor the company you work for, keep your fork/repository **private** and restrict access to the generated outputs. Findings, reports, deduplication state, logs, and CSV/JSON exports may contain sensitive information, including leaked credentials, internal names, URLs, or other data that should not be exposed publicly.

This tool is provided for defensive security and authorized OSINT workflows. You are solely responsible for how you use it, how you store the results, and whether your usage complies with applicable laws, contracts, internal policies, and disclosure processes. The maintainer assumes no responsibility or liability for misuse, unauthorized scanning, disclosure of sensitive data, or any consequences resulting from the use of this tool.

---

## Quick start

```bash
git clone https://github.com/clivoa/harppia.git
cd harppia
pip install -r requirements.txt

python harppia.py -k target-name -k target-domain.example
```

No configuration required for a first run. Add `--gh-pat` to unlock GitHub search and gist scanning at higher rate limits.

---

## Project structure

```
harppia/
├── harppia.py                     ← ad-hoc CLI entry point
├── compile.py                     ← aggregates daily findings into CSV reports
├── requirements.txt               ← requests only
├── seen_hashes.json               ← deduplication state (committed by CI)
├── scanners/
│   ├── swaggerhub.py              ← SwaggerHub scanner
│   ├── github_search.py           ← GitHub Code Search scanner
│   ├── github_gist.py             ← GitHub Gist scanner
│   └── formatters.py              ← JSON/YAML formatter paste site scanner
├── utils/
│   ├── keywords.py                ← keyword list to scan for
│   ├── patterns.py                ← 68 detection regexes + category mapping
│   ├── telegram.py                ← Telegram alert helper
│   └── deduplication.py           ← SHA256-based cross-run dedup
└── .github/workflows/
    ├── swaggerhub-scanner.yml     ← cron :00
    ├── gist-scanner.yml           ← cron :15
    ├── github-search-scanner.yml  ← cron :30
    ├── formatter-scanner.yml      ← cron :45
    └── compile-reports.yml        ← cron :55
```

---

## Ad-hoc usage

The `harppia.py` CLI lets you scan on demand — no GitHub account, no secrets, no commits needed.

### Basic usage

```bash
# Scan across all four sources
python harppia.py -k target-name -k target-domain.example

# Target specific scanners
python harppia.py -k target-name --scanner swaggerhub,gists

# Save to file
python harppia.py -k target-name --output findings.json
python harppia.py -k target-name --output findings.csv --format csv

# Save only high-confidence secrets
python harppia.py -k target-name --category credential --output secrets.json

# Save SwaggerHub URLs discovered during the scan
python harppia.py -k target-name --scanner swaggerhub --candidates-output swaggerhub-candidates.json

# Ignore previously seen findings (fresh scan)
python harppia.py -k target-name --no-dedup

# Suppress Telegram alerts for this run
python harppia.py -k target-name --no-alert

# Pass credentials inline — no env vars needed
python harppia.py -k target-name \
  --gh-pat ghp_xxxxxxxxxxxx \
  --telegram-token 123456789:ABCdef \
  --telegram-chat -1001234567890

# Extend the GitHub Code Search time window
python harppia.py -k target-name --since-hours 72

# Skip the Gist public timeline pass (keyword search only, faster)
python harppia.py -k target-name --gist-hours 0
```

### Help output

```text
usage: harppia [-h] [-k KEYWORD] [-s SCANNER] [-o FILE] [--candidates-output FILE]
               [--format {json,csv}] [--category CATEGORY] [--no-dedup] [--no-alert]
               [--gh-pat TOKEN] [--telegram-token TOKEN] [--telegram-chat CHAT_ID]
               [--since-hours N] [--gist-hours N]

Ad-hoc OSINT credential scanner — no GitHub Actions required.

optional arguments:
  -h, --help            show this help message and exit
  -k KEYWORD, --keyword KEYWORD
                        Keyword to scan (repeat for multiple). Defaults to utils/keywords.py if
                        omitted.
  -s SCANNER, --scanner SCANNER
                        Scanners to run: swaggerhub, github, gists, formatters, all (default:
                        all). Comma-separated or repeat the flag.
  -o FILE, --output FILE
                        Save findings to FILE (JSON by default, CSV with --format csv).
  --candidates-output FILE
                        Save discovered candidate URLs/metadata to FILE (SwaggerHub currently).
  --format {json,csv}   Output file format (default: json).
  --category CATEGORY   Only print/save findings from category: credential, token, pii,
                        infrastructure. Comma-separated or repeat the flag.
  --no-dedup            Disable cross-run deduplication — scan everything fresh.
  --no-alert            Suppress Telegram alerts for this run.
  --gh-pat TOKEN        GitHub PAT (overrides GH_PAT env var).
  --telegram-token TOKEN
                        Telegram bot token (overrides TELEGRAM_BOT_TOKEN env var).
  --telegram-chat CHAT_ID
                        Telegram chat/channel ID (overrides TELEGRAM_CHAT_ID env var).
  --since-hours N       GitHub Code Search: look back N hours (default: 24). Use 0 for no time
                        filter.
  --gist-hours N        Gist timeline: scan gists updated in the last N hours (default: 6). Use 0
                        to skip timeline.

scanners: swaggerhub, github, gists, formatters, all (default: all)

examples:
  python harppia.py -k target-name -k target-domain.example
  python harppia.py -k target-name --scanner swaggerhub,gists
  python harppia.py -k target-name --no-dedup --output findings.json
  python harppia.py -k target-name --gh-pat ghp_xxx --since-hours 72
```

### All options

| Flag | Default | Description |
|---|---|---|
| `-k / --keyword` | `utils/keywords.py` | Keyword to scan. Repeat for multiple. Falls back to `utils/keywords.py` if omitted. |
| `-s / --scanner` | `all` | Scanners to run: `swaggerhub`, `github`, `gists`, `formatters`, or `all`. Comma-separated or repeated. |
| `-o / --output` | — | Save findings to a file. |
| `--candidates-output` | — | Save discovered candidate URLs/metadata to a JSON file (SwaggerHub currently). |
| `--format` | `json` | Output file format: `json` or `csv`. |
| `--category` | all | Only print/save findings from one or more categories: `credential`, `token`, `pii`, `infrastructure`. Comma-separated or repeated. |
| `--no-dedup` | off | Skip cross-run deduplication — scan everything fresh. |
| `--no-alert` | off | Suppress Telegram alerts for this run. |
| `--gh-pat` | `$GH_PAT` | GitHub Personal Access Token. |
| `--telegram-token` | `$TELEGRAM_BOT_TOKEN` | Telegram bot token. |
| `--telegram-chat` | `$TELEGRAM_CHAT_ID` | Telegram chat/channel ID. |
| `--since-hours` | `24` | GitHub Code Search time window in hours. `0` = no time filter. |
| `--gist-hours` | `6` | Gist public timeline window in hours. `0` = skip timeline, keyword search only. |

---

## Automated scanning with GitHub Actions

For continuous monitoring, fork this repo and configure it to run on a schedule. Each scanner runs every 6 hours at a staggered offset to avoid simultaneous API pressure. Findings are committed back to the repo automatically; a 5th workflow compiles daily CSV reports.

### 1. Fork this repository

Keep your fork **private** — it will contain finding data linked to real leaked credentials.

### 2. Configure your keywords

Edit `utils/keywords.py` and add the organization names, brands, and domain fragments you want to monitor.

```python
KEYWORDS = [
    # ── Primary targets ────────────────────────────────────────────────────────
    "target-name",
    "target-brand",

    # ── Domain identifiers (appear in env vars and connection strings) ─────────
    "target-domain.example",
    "service.target-domain.example",
]
```

**Tips for effective keywords:**
- Specific sub-brand names produce less noise than generic words.
- Domain fragments (e.g. `target-domain.example`) catch credentials in connection strings and email addresses.
- Internal platform names (payment systems, internal APIs) surface developer configs that brand names alone miss.
- Every keyword multiplies GitHub API calls — keep the list focused.

### 3. Create a Telegram bot

1. Open Telegram and start a chat with [@BotFather](https://t.me/BotFather).
2. Send `/newbot` and follow the prompts. Copy the **bot token** (format: `123456789:ABCdef...`).
3. Add the bot to the channel or group where alerts should be delivered.
4. Get your **chat ID**:
   - For a channel: forward any message to [@userinfobot](https://t.me/userinfobot).
   - Alternatively, call `https://api.telegram.org/bot<TOKEN>/getUpdates` after sending a message to the bot.
   - Channel IDs start with `-100`.

### 4. Generate a GitHub Personal Access Token (PAT)

The GitHub Search and Gist scanners use a PAT to access the API at higher rate limits (30 req/min authenticated vs 10 unauthenticated). The token only needs read access to public content.

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**.
2. Click **Generate new token**.
3. Set a name (e.g. `harppia-scanner`) and select **Public Repositories (read-only)** under Repository access.
4. Copy the token.

> A classic PAT with `public_repo` scope also works.

### 5. Add GitHub Secrets

Go to your repository → **Settings → Secrets and variables → Actions → New repository secret**.

| Secret | Value |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Channel/chat ID |
| `GH_PAT` | GitHub PAT from step 4 |

### 6. Enable GitHub Actions

Go to the **Actions** tab in your repository and click **Enable workflows** if prompted.

Each workflow runs automatically at its scheduled time. You can also trigger any workflow manually via **Actions → [workflow name] → Run workflow**.

### Workflow schedule

| Workflow | Cron | Scanner |
|---|---|---|
| `swaggerhub-scanner.yml` | `:00` every 6h | SwaggerHub |
| `gist-scanner.yml` | `:15` every 6h | GitHub Gists |
| `github-search-scanner.yml` | `:30` every 6h | GitHub Code Search |
| `formatter-scanner.yml` | `:45` every 6h | Formatter paste sites |
| `compile-reports.yml` | `:55` every 6h | Report aggregation |

---

## Understanding findings

### Output structure

```
data/
  swaggerhub/
    2026-07-02_matches.json
  github_search/
    2026-07-02_matches.json
  github_gists/
    2026-07-02_matches.json
  formatters_2026-07-02_matches.json
reports/
  2026-07-02_credential.csv    ← Telegram alerts were sent for these rows
  2026-07-02_token.csv
  2026-07-02_pii.csv
  2026-07-02_infrastructure.csv
  2026-07-02_summary.json
seen_hashes.json                ← deduplication state (committed by CI)
```

When using the CLI (`harppia.py`), findings are printed to the terminal. Use `--output` to save them to a file. The `data/` and `reports/` directories are only created by the scheduled scanners or when running individual scanners directly.

### Finding schema

```json
{
  "source": "swaggerhub",
  "keyword": "target-name",
  "url": "https://app.swaggerhub.com/apis/...",
  "pattern_name": "generic_api_key",
  "matched_value": "api_key=example-value",
  "category": "credential",
  "timestamp": "2026-07-02T12:00:00+00:00"
}
```

### Categories

| Category | What it captures | Alert |
|---|---|---|
| `credential` | API keys, passwords, private keys, DB connection strings, payment secrets | Telegram + CSV |
| `token` | Bearer tokens, JWTs, session IDs — common in API documentation, lower signal | CSV only |
| `pii` | Email addresses, CPF, CNPJ | CSV only |
| `infrastructure` | IP addresses, object-storage URLs | CSV only |

---

## Detection patterns

68 patterns are defined in `utils/patterns.py`, covering:

- **Cloud and infrastructure credentials**: access key IDs, secret keys, service-account indicators, storage connection strings, object-storage URLs, and network indicators.
- **Private keys**: common PEM/private-key block formats and related key material indicators.
- **Developer and automation tokens**: source-control tokens, package-registry tokens, issue-tracker tokens, bot tokens, webhooks, and embedded URL credentials.
- **Communication and notification secrets**: messaging, email-delivery, telephony, and bot credentials.
- **Payment and financial API credentials**: processor tokens, merchant keys, client IDs, client secrets, and payment-related environment variables.
- **Database connection strings**: SQL, document-store, cache, and JDBC-style URIs with embedded credentials.
- **AI and application platform keys**: model-provider API keys, backend service keys, and application platform service credentials.
- **Secrets-manager and observability values**: vault-style tokens, monitoring DSNs, API tokens, and service-role keys.
- **Leak indicators**: credential JSON blocks, certificate paths, local package-auth files, and other high-signal configuration fragments.
- **Generic assignments**: `secret_key`, `api_key`, and `password` assignment patterns with false-positive guards.

### Adding a pattern

Both `PATTERNS` (regex) and `PATTERN_CATEGORY` (category string) in `utils/patterns.py` must be updated together. An assertion at module load time enforces this:

```python
# In PATTERN_CATEGORY
"my_pattern": "credential",

# In PATTERNS
"my_pattern": r"MY_PREFIX_[A-Za-z0-9]{32}",
```

If the two dicts fall out of sync, an `AssertionError` is raised immediately on import.

---

## Deduplication

Each finding is hashed as `SHA256(source | normalized_url | pattern_name)` and stored in `seen_hashes.json`. Subsequent runs skip any hash already present — the same secret in the same file will not be re-alerted.

GitHub raw URLs are normalized (commit SHA stripped) so the same file across different commits maps to the same hash.

SwaggerHub specs and Gist files that have been fully scanned are also marked with a `__SCANNED__` sentinel, so they are skipped entirely on the next run without re-fetching the content.

The CLI (`harppia.py`) participates in the same deduplication by default. Pass `--no-dedup` for a fresh scan that ignores history.

---

## Rate limits

| API | Unauthenticated | Authenticated (PAT) |
|---|---|---|
| GitHub Code Search | 10 req/min | 30 req/min |
| GitHub Gists timeline | 60 req/hour | 5,000 req/hour |
| SwaggerHub | No auth required | — |

The scanners include `time.sleep()` calls between requests to stay within these limits. If you add many keywords:
- Reduce `TIMELINE_PAGES` in `scanners/github_gist.py` to scan fewer gist timeline pages.
- Reduce `EXTENSIONS` in `scanners/github_search.py` to search fewer file types per keyword.
- SwaggerHub is capped to the top 100 results per keyword (`MAX_PAGES = 1`) — already optimized.

---

## License

MIT — see [LICENSE](LICENSE).
