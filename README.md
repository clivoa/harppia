# harppia

<p align="center">
  <img src="harppia.png" alt="harppia" width="640">
</p>

OSINT credential scanner — monitors public sources for leaked secrets matching your keywords.

Harppia scans seven surfaces — SwaggerHub API specs, GitHub code search, public Gists, JSON/YAML formatter paste sites, Sourcegraph (multi-platform code search), the npm registry, and optionally Pastebin — looking for API keys, tokens, passwords, and other secrets associated with the organizations, brands, domains, or identifiers you define. It runs either **on demand from the command line** or **automatically via GitHub Actions** on a schedule.

Findings are categorized by signal strength. Only high-confidence credentials trigger a Telegram alert — noisier categories (bearer tokens, JWTs, IP addresses) are logged to CSV for offline review.

Matched secret values are redacted by default in terminal output, JSON/CSV exports, reports, and Telegram alerts. Each redacted finding includes `matched_value_hash` so you can correlate repeat values without exposing the raw secret.

---

## Responsible use

Use Harppia only on assets, brands, domains, and organizations you are authorized to monitor. If you use this project to monitor the company you work for, keep your fork/repository **private** and restrict access to the generated outputs. Findings, reports, deduplication state, logs, and CSV/JSON exports may contain sensitive information, including leaked credentials, internal names, URLs, or other data that should not be exposed publicly.

This tool is provided for defensive security and authorized OSINT workflows. You are solely responsible for how you use it, how you store the results, and whether your usage complies with applicable laws, contracts, internal policies, and disclosure processes. The maintainer assumes no responsibility or liability for misuse, unauthorized scanning, disclosure of sensitive data, or any consequences resulting from the use of this tool.

---

## Quick start

```bash
git clone https://github.com/clivoa/harppia.git
cd harppia
python3 -m pip install -r requirements.txt

python3 harppia.py -k target-name -k target-domain.example
```

No configuration required for a first run. Add `--gh-pat` to unlock GitHub search and gist scanning at higher rate limits.

---

## Project structure

```
harppia/
├── harppia.py                     ← ad-hoc CLI entry point
├── compile.py                     ← aggregates daily findings into CSV reports
├── requirements.txt               ← requests only
├── .env.example                   ← optional environment variable reference
├── SECURITY.md                    ← security and responsible disclosure notes
├── CONTRIBUTING.md                ← development and PR guidance
├── seen_hashes.json               ← deduplication state (committed by CI)
├── scanners/
│   ├── swaggerhub.py              ← SwaggerHub scanner
│   ├── github_search.py           ← GitHub Code Search scanner
│   ├── github_gist.py             ← GitHub Gist scanner
│   ├── formatters.py              ← JSON/YAML formatter paste site scanner
│   ├── sourcegraph.py             ← Sourcegraph multi-platform code search
│   ├── npm_registry.py            ← npm public package registry scanner
│   └── pastebin.py                ← Pastebin scanner (ad-hoc only — see below)
├── utils/
│   ├── keywords.py                ← keyword list to scan for
│   ├── patterns.py                ← 68 detection regexes + category mapping
│   ├── keyword_match.py           ← boundary-aware keyword matching
│   ├── redaction.py               ← matched-value redaction helpers
│   ├── telegram.py                ← Telegram alert helper
│   └── deduplication.py           ← SHA256-based cross-run dedup
├── tests/                         ← unit tests for matching, redaction, dedup, reports
└── .github/workflows/
    ├── swaggerhub-scanner.yml     ← cron :00
    ├── gist-scanner.yml           ← cron :15
    ├── github-search-scanner.yml  ← cron :30
    ├── formatter-scanner.yml      ← cron :45
    ├── sourcegraph-scanner.yml    ← cron every 12h
    ├── npm-scanner.yml            ← cron daily
    ├── compile-reports.yml        ← cron :55
    └── quality.yml                ← compile + unit tests on push/PR
```

---

## Ad-hoc usage

The `harppia.py` CLI lets you scan on demand — no GitHub account, no secrets, no commits needed.

Keyword confirmation is boundary-aware: short terms match token-like occurrences but not unrelated substrings inside longer alphanumeric words. Domain keywords also avoid matching inside longer domains.

### Basic usage

```bash
# Scan across all sources (swaggerhub, github, gists, formatters, sourcegraph, npm)
python3 harppia.py -k target-name -k target-domain.example

# Target specific scanners
python3 harppia.py -k target-name --scanner swaggerhub,gists
python3 harppia.py -k target-name --scanner sourcegraph,npm

# Save to file
python3 harppia.py -k target-name --output findings.json
python3 harppia.py -k target-name --output findings.csv --format csv

# Save only high-confidence secrets
python3 harppia.py -k target-name --category credential --output secrets.json

# Reveal full matched values for controlled local triage
python3 harppia.py -k target-name --category credential --show-secrets

# Save SwaggerHub URLs discovered during the scan
python3 harppia.py -k target-name --scanner swaggerhub --candidates-output swaggerhub-candidates.json

# Ignore previously seen findings (fresh scan)
python3 harppia.py -k target-name --no-dedup

# Suppress Telegram alerts for this run
python3 harppia.py -k target-name --no-alert

# Pass credentials inline — no env vars needed
python3 harppia.py -k target-name \
  --gh-pat ghp_xxxxxxxxxxxx \
  --telegram-token 123456789:ABCdef \
  --telegram-chat -1001234567890

# Extend the GitHub Code Search time window
python3 harppia.py -k target-name --since-hours 72

# Skip the Gist public timeline pass (keyword search only, faster)
python3 harppia.py -k target-name --gist-hours 0

# Pastebin (requires Pro account + whitelisted IP — see below)
python3 harppia.py -k target-name --scanner pastebin
```

### All options

| Flag | Default | Description |
|---|---|---|
| `-k / --keyword` | `utils/keywords.py` | Keyword to scan. Repeat for multiple. Falls back to `utils/keywords.py` if omitted. |
| `-s / --scanner` | `all` | Scanners to run: `swaggerhub`, `github`, `gists`, `formatters`, `sourcegraph`, `npm`, or `all`. Use `pastebin` explicitly (see below). Comma-separated or repeated. |
| `-o / --output` | — | Save findings to a file. |
| `--candidates-output` | — | Save discovered candidate URLs/metadata to a JSON file (SwaggerHub currently). |
| `--format` | `json` | Output file format: `json` or `csv`. |
| `--category` | all | Only print/save findings from one or more categories: `credential`, `token`, `pii`, `infrastructure`. Comma-separated or repeated. |
| `--no-dedup` | off | Skip cross-run deduplication — scan everything fresh. |
| `--no-alert` | off | Suppress Telegram alerts for this run. |
| `--show-secrets` | off | Print and save full matched secret values. By default, `matched_value` is redacted and `matched_value_hash` is added for correlation. |
| `--gh-pat` | `$GH_PAT` | GitHub Personal Access Token. |
| `--telegram-token` | `$TELEGRAM_BOT_TOKEN` | Telegram bot token. |
| `--telegram-chat` | `$TELEGRAM_CHAT_ID` | Telegram chat/channel ID. |
| `--since-hours` | `24` | GitHub Code Search time window in hours. `0` = no time filter. |
| `--gist-hours` | `6` | Gist public timeline window in hours. `0` = skip timeline, keyword search only. |

---

## Scanners

| Scanner | `--scanner` | Automated | What it searches |
|---|---|---|---|
| SwaggerHub | `swaggerhub` | every 6h | Public API specs on SwaggerHub |
| GitHub Code Search | `github` | every 6h | Source files in public GitHub repos |
| GitHub Gists | `gists` | every 6h | Public Gists (timeline + keyword search) |
| Formatter sites | `formatters` | every 6h | Recent pastes on jsonformatter.org (YAML/XML endpoints) |
| Sourcegraph | `sourcegraph` | every 12h | Public code across GitHub, GitLab, Bitbucket, and more |
| npm registry | `npm` | daily | Package metadata and READMEs on the npm public registry |
| Pastebin | `pastebin` | ❌ ad-hoc only | Recent public pastes on Pastebin (see below) |

### Pastebin

The Pastebin scanner uses the [Pastebin Scraping API](https://pastebin.com/doc_scraping_api), which requires:

1. A **Pastebin Pro account** (subscriber tier).
2. Your runner's **IP address whitelisted** in your Pastebin account settings.

Because of the IP whitelist requirement, the Pastebin scanner is intentionally **excluded from `--scanner all`** and from the automated GitHub Actions schedule (GitHub Actions uses dynamic IPs that cannot be reliably whitelisted). It is only available when invoked explicitly:

```bash
PASTEBIN_API_KEY=your_key python3 harppia.py -k target-name --scanner pastebin
```

To use it, whitelist the IP of the machine you are running it from at [pastebin.com/doc_scraping_api](https://pastebin.com/doc_scraping_api). If you run it from a server with a fixed IP, add that IP to the whitelist and set the `PASTEBIN_API_KEY` environment variable.

---

## Automated scanning with GitHub Actions

For continuous monitoring, fork this repo and configure it to run on a schedule. Findings are committed back to the repo automatically; a separate workflow compiles daily CSV reports.

Scanner workflows share a single `harppia-writes` concurrency group so scheduled runs do not push to the repository at the same time. A separate `quality.yml` workflow compiles the code and runs unit tests on pushes, pull requests, and manual dispatch.

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

| Secret | Value | Required by |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather | All scanners (alerts) |
| `TELEGRAM_CHAT_ID` | Channel/chat ID | All scanners (alerts) |
| `GH_PAT` | GitHub PAT from step 4 | GitHub Search, Gists |
| `SOURCEGRAPH_TOKEN` | Sourcegraph access token (optional) | Sourcegraph (higher rate limits) |

See `.env.example` for the same variables when running locally. Harppia reads environment variables directly; export them in your shell or pass CLI flags such as `--gh-pat`, `--telegram-token`, and `--telegram-chat`.

### 6. Enable GitHub Actions

Go to the **Actions** tab in your repository and click **Enable workflows** if prompted.

Each workflow runs automatically at its scheduled time. You can also trigger any workflow manually via **Actions → [workflow name] → Run workflow**.

### Workflow schedule

| Workflow | Schedule | Scanner |
|---|---|---|
| `swaggerhub-scanner.yml` | `:00` every 6h | SwaggerHub |
| `gist-scanner.yml` | `:15` every 6h | GitHub Gists |
| `github-search-scanner.yml` | `:30` every 6h | GitHub Code Search |
| `formatter-scanner.yml` | `:45` every 6h | Formatter paste sites |
| `sourcegraph-scanner.yml` | `:15` every 12h | Sourcegraph |
| `npm-scanner.yml` | `08:30` daily | npm registry |
| `compile-reports.yml` | `:55` every 6h | Report aggregation |
| `quality.yml` | push / PR / manual | Syntax + unit tests |

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
  sourcegraph/
    2026-07-02_matches.json
  npm/
    2026-07-02_matches.json
  pastebin/
    2026-07-02_matches.json        ← only present when run ad-hoc
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
  "source": "sourcegraph",
  "keyword": "target-name",
  "url": "https://sourcegraph.com/github.com/user/repo/-/blob/config/app.yml",
  "repository": "github.com/user/repo",
  "path": "config/app.yml",
  "pattern_name": "generic_api_key",
  "matched_value": "api_...alue (21 chars)",
  "matched_value_hash": "c38f4f6a16...",
  "category": "credential",
  "timestamp": "2026-07-02T12:00:00+00:00"
}
```

`matched_value` is redacted by default in terminal output, saved JSON/CSV, reports, and Telegram alerts. Use `--show-secrets` only for controlled local triage when the exact leaked value is required. When running an individual scanner module directly, set `HARPPIA_SHOW_SECRETS=1` only if you intentionally want raw values written to disk.

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

Each finding is hashed as `SHA256(source | normalized_url | pattern_name | matched_value)` and stored in `seen_hashes.json`. Subsequent runs skip any hash already present — the same secret in the same file will not be re-alerted, while a new value of the same pattern can still be detected.

GitHub raw URLs are normalized (commit SHA stripped) so the same file across different commits maps to the same hash.

Mutable sources such as SwaggerHub specs and Gist files are revisited on later runs so newly added secrets are not missed. Deduplication suppresses repeat alerts for values already seen.

The CLI (`harppia.py`) participates in the same deduplication by default. Pass `--no-dedup` for a fresh scan that ignores history.

---

## Rate limits

| Source | Unauthenticated | Authenticated |
|---|---|---|
| GitHub Code Search | 10 req/min | 30 req/min (with `GH_PAT`) |
| GitHub Gists timeline | 60 req/hour | 5,000 req/hour (with `GH_PAT`) |
| SwaggerHub | No auth required | — |
| Sourcegraph | Free tier (limited) | Higher limits (with `SOURCEGRAPH_TOKEN`) |
| npm registry | No auth required | — |
| Pastebin Scraping API | IP whitelist required | Requires Pro account |

The scanners include `time.sleep()` calls between requests to stay within these limits. If you add many keywords:
- Reduce `TIMELINE_PAGES` in `scanners/github_gist.py` to scan fewer gist timeline pages.
- Reduce `EXTENSIONS` in `scanners/github_search.py` to search fewer file types per keyword.
- SwaggerHub requests the top 100 `BEST_MATCH` specs per keyword.
- Sourcegraph is capped at 50 results per keyword by default (`_COUNT` in `scanners/sourcegraph.py`).
- npm is capped at 50 full metadata fetches per keyword (`_MAX_FULL_FETCH` in `scanners/npm_registry.py`).

---

## Development

Run the same checks used by the quality workflow:

```bash
python3 -m py_compile harppia.py compile.py scanners/*.py utils/*.py tests/*.py
python3 -m unittest discover -s tests
```

Tests cover redaction, deduplication, report loading (all sources), GitHub Search URL/content handling, and boundary-aware keyword matching.

---

## License

MIT — see [LICENSE](LICENSE).
