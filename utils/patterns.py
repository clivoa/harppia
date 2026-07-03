import re

# Categories:
#   credential  → actual secret/key/password → Telegram alert
#   token       → bearer/JWT/SID, common in API docs, lower signal → file only
#   pii         → CPF, CNPJ, email → file only
#   infrastructure → URLs, IPs, bucket names → file only
PATTERN_CATEGORY: dict[str, str] = {
    # ── Cloud / infrastructure ────────────────────────────────────────────────
    "aws_access_key_id": "credential",         # AKIA/ASIA prefix — very specific
    "aws_secret_access_key": "credential",     # context-aware: requires var name
    "google_api_key": "credential",            # AIza prefix — very specific
    "google_oauth_token": "credential",        # ya29. prefix — short-lived but still a leak
    "firebase_server_key": "credential",       # AAAA prefix — FCM push key
    "gcp_service_account": "credential",       # leaked GCP JSON cred file indicator
    "azure_storage_connection": "credential",  # DefaultEndpointsProtocol= format
    "digitalocean_spaces_key": "credential",   # DO Spaces access key with context
    # ── Private keys ─────────────────────────────────────────────────────────
    "rsa_private_key": "credential",
    "dsa_private_key": "credential",
    "ec_private_key": "credential",
    "openssh_private_key": "credential",       # modern ssh-keygen format
    "pgp_private_key": "credential",
    "generic_private_key": "credential",       # catch-all BEGIN * PRIVATE KEY
    # ── Code / dev platform tokens ───────────────────────────────────────────
    "github_pat_classic": "credential",        # ghp_ prefix
    "github_pat_fine_grained": "credential",   # github_pat_ prefix
    "github_url_credential": "credential",     # user:token@github.com
    "npm_token": "credential",                 # npm_ prefix
    "jira_pat": "credential",                  # ATATTAC prefix
    # ── Messaging / email ─────────────────────────────────────────────────────
    "slack_bot_token": "credential",           # xoxb-/xoxp- with JSON context
    "slack_webhook": "credential",             # hooks.slack.com specific URL
    "sendgrid_api_key": "credential",          # SG. three-part format — near zero FP
    "mailgun_api_key": "credential",           # key- prefix with 32 hex chars
    "telegram_bot_token": "credential",        # numeric_id:hash format
    # ── Payment processors ───────────────────────────────────────────────────
    "stripe_secret_key": "credential",         # sk_live_ prefix
    "stripe_restricted_key": "credential",     # rk_live_ prefix
    "paypal_braintree_token": "credential",    # access_token$production$ format
    "square_oauth_secret": "credential",       # sq0csp- prefix
    # ── Brazilian payment / fintech ───────────────────────────────────────────
    "galax_hash": "credential",               # GalaxPay production hash
    "celcoin_client_secret": "credential",    # Celcoin hex secret
    "celcoin_client_id": "credential",        # Celcoin client_id with domain suffix
    "mercadopago_access_token": "credential", # APP_USR- format
    "pagarme_api_key": "credential",          # ak_live_/ak_test_ prefix
    "asaas_api_key": "credential",            # $aas_ prefix
    "pix_key_env": "credential",              # PIX key in env var context
    # ── Database URIs (credentials embedded in URL) ───────────────────────────
    "mysql_uri": "credential",
    "postgres_uri": "credential",
    "mongodb_uri": "credential",
    "redis_uri": "credential",
    "jdbc_uri": "credential",
    # ── AI / LLM API keys ────────────────────────────────────────────────────
    "openai_api_key": "credential",           # sk- prefix, common in app configs
    "anthropic_api_key": "credential",        # sk-ant- prefix
    # ── HashiCorp / secrets managers ─────────────────────────────────────────
    "vault_token": "credential",              # hvs./hvb./hvr. prefix
    # ── Brazilian acquirers / gateways ───────────────────────────────────────
    "cielo_merchant_key": "credential",
    "stone_client_secret": "credential",
    "efi_client_secret": "credential",
    # ── Cloud / infra ─────────────────────────────────────────────────────────
    "digitalocean_pat": "credential",
    "cloudflare_api_token": "credential",
    "supabase_service_key": "credential",
    "sentry_dsn": "credential",
    "resend_api_key": "credential",
    "npmrc_auth_token": "credential",
    # ── Leak indicators ───────────────────────────────────────────────────────
    "private_key_in_json": "credential",
    "pix_certificate_path": "credential",
    "twilio_auth_token": "credential",
    # ── Generic high-signal patterns ─────────────────────────────────────────
    "generic_secret_key": "credential",
    "generic_api_key": "credential",
    "possible_password": "credential",
    # ── Token category (noisy in API docs — log only) ─────────────────────────
    "authorization_bearer": "token",
    "authorization_basic": "token",
    "json_web_token": "token",
    "facebook_access_token": "token",
    "twilio_api_key": "token",               # SK prefix too generic for credential
    # ── PII ───────────────────────────────────────────────────────────────────
    "email": "pii",
    "cpf": "pii",
    "cnpj": "pii",
    # ── Infrastructure ────────────────────────────────────────────────────────
    "ip_address": "infrastructure",
    "aws_s3_url": "infrastructure",
}

PATTERNS: dict[str, str] = {
    # ── Cloud / infrastructure ────────────────────────────────────────────────
    "aws_access_key_id": r"A[SK]IA[0-9A-Z]{16}",
    "aws_secret_access_key": r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "google_oauth_token": r"ya29\.[0-9A-Za-z\-_]{50,}",
    "firebase_server_key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "gcp_service_account": r'"type"\s*:\s*"service_account"',
    "azure_storage_connection": (
        r"DefaultEndpointsProtocol=https;AccountName=[^;]{3,24};"
        r"AccountKey=[A-Za-z0-9+/=]{88}"
    ),
    "digitalocean_spaces_key": r"(?i)spaces[_-]?(?:key|access)[_-]?(?:id)?\s*[=:]\s*[A-Z0-9]{20}\b",
    # ── Private keys ─────────────────────────────────────────────────────────
    "rsa_private_key": r"-----BEGIN RSA PRIVATE KEY-----",
    "dsa_private_key": r"-----BEGIN DSA PRIVATE KEY-----",
    "ec_private_key": r"-----BEGIN EC PRIVATE KEY-----",
    "openssh_private_key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "pgp_private_key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "generic_private_key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
    # ── Code / dev platform tokens ───────────────────────────────────────────
    "github_pat_classic": r"ghp_[A-Za-z0-9]{36}",
    "github_pat_fine_grained": r"github_pat_[A-Za-z0-9_]{82}",
    "github_url_credential": r"https?://[A-Za-z0-9_-]+:[A-Za-z0-9_\-]+@github\.com",
    "npm_token": r"npm_[A-Za-z0-9]{36}",
    "jira_pat": r"ATATTAC[A-Za-z0-9]{24,48}",
    # ── Messaging / email ─────────────────────────────────────────────────────
    "slack_bot_token": r'"api_token"\s*:\s*"(xox[bpoa]-[A-Za-z0-9\-]+)"',
    "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}",
    "sendgrid_api_key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "mailgun_api_key": r"key-[0-9a-zA-Z]{32}",
    "telegram_bot_token": r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
    # ── Payment processors ───────────────────────────────────────────────────
    "stripe_secret_key": r"sk_live_[0-9a-zA-Z]{24}",
    "stripe_restricted_key": r"rk_live_[0-9a-zA-Z]{24}",
    "paypal_braintree_token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "square_oauth_secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    # ── Brazilian payment / fintech ───────────────────────────────────────────
    "galax_hash": r"GALAX_HASH\s*[=:]\s*[A-Za-z0-9]{20,}",
    "celcoin_client_secret": r"(?i)client_secret\s*[=:]\s*[a-f0-9]{32,64}",
    "celcoin_client_id": r"(?i)client_id\s*[=:\"'`\s]+[a-f0-9]{16,}\.(?:teste|prod)\.celcoinapi",
    "mercadopago_access_token": r"APP_USR-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-\d+",
    "pagarme_api_key": r"ak_(?:live|test)_[A-Za-z0-9]{32}",
    "asaas_api_key": r"\$aas_(?:prod_|dev_)?[A-Za-z0-9]{32,}",
    "pix_key_env": r"(?i)pix[_-]?key\s*[=:\"'`]+\s*[^\s\"'`]{10,}",
    # ── Database URIs ─────────────────────────────────────────────────────────
    "mysql_uri": r"mysql://[A-Za-z0-9_]+:[^\s@]{3,}@[^\s/]+/[A-Za-z0-9_]+",
    "postgres_uri": r"postgres(?:ql)?://[A-Za-z0-9_]+:[^\s@]{3,}@[^\s/]+/[A-Za-z0-9_]+",
    "mongodb_uri": r"mongodb(?:\+srv)?://[A-Za-z0-9_-]+:[^\s@]{3,}@[^\s/]+",
    "redis_uri": r"redis://[A-Za-z0-9_-]+:[^\s@]{3,}@[^\s/:]+",
    "jdbc_uri": r"jdbc:(?:postgresql|mysql|sqlserver)://[^\s@]+:[^\s@]{3,}@[^\s/]+",
    # ── AI / LLM ─────────────────────────────────────────────────────────────
    "openai_api_key": r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{40,}",
    "anthropic_api_key": r"sk-ant-(?:api[0-9]+-)?[A-Za-z0-9_-]{90,}",
    # ── HashiCorp Vault ───────────────────────────────────────────────────────
    "vault_token": r"\bh(?:vs|vb|vr)\.[A-Za-z0-9_-]{90,}\b",
    # ── Brazilian acquirers / gateways ───────────────────────────────────────
    "cielo_merchant_key": r"(?i)cielo[_-]?(?:merchant[_-]?)?key\s*[=:]\s*[0-9a-f\-]{36}",
    "stone_client_secret": r"(?i)stone[_-]?(?:client[_-]?)?secret\s*[=:]\s*[A-Za-z0-9_\-]{20,}",
    "efi_client_secret": r"(?i)(?:efi|gerencianet)[_-]?client[_-]?secret\s*[=:]\s*[A-Za-z0-9_]{20,}",
    # ── Cloud / infra ─────────────────────────────────────────────────────────
    "digitalocean_pat": r"dop_v1_[a-f0-9]{64}",
    "cloudflare_api_token": r"(?i)(?:CF|CLOUDFLARE)[_-]?API[_-]?TOKEN\s*[=:]\s*[A-Za-z0-9_-]{40}",
    "supabase_service_key": r"(?i)SUPABASE[_-]?SERVICE[_-]?(?:ROLE[_-]?)?KEY\s*[=:]\s*eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "sentry_dsn": r"https://[a-f0-9]{32}@o\d+\.ingest(?:\.us)?\.sentry\.io/\d+",
    "resend_api_key": r"re_[A-Za-z0-9_]{36}",
    "npmrc_auth_token": r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-]{36}",
    # ── Leak indicators ───────────────────────────────────────────────────────
    "private_key_in_json": r'"private_key"\s*:\s*"-----BEGIN',
    "pix_certificate_path": r"(?i)(?:cert(?:ificado)?|pfx|p12)[_-]?(?:pix|digital)?\s*[=:]\s*/[^\s]{5,}\.(?:pfx|p12|pem|crt|cer)",
    "twilio_auth_token": r"(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*[a-f0-9]{32}",
    # ── Generic high-signal (need assignment context to reduce FP) ────────────
    "generic_secret_key": r"(?i)secret[_-]?key\s*[=:\"'`]\s*[^\s\"'`,]{12,}",
    "generic_api_key": r"(?i)api[_-]?key\s*[=:\"'`]\s*[^\s\"'`,]{12,}",
    "possible_password": (
        r"(?i)(?:^|\s)(?:password|passwd|pwd)\s*[=:\"'`]+\s*(?!your|example|change|replace|here|xxx|test|sample)[^\s\"'`]{6,}"
    ),
    # ── Token (noisy in API docs — log only) ─────────────────────────────────
    "authorization_bearer": r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=+\/]{20,}",
    "authorization_basic": r"(?i)\bbasic\s+[A-Za-z0-9=:_+\/\-]{10,}",
    "json_web_token": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    "facebook_access_token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "twilio_api_key": r"\bSK[0-9a-fA-F]{32}\b",
    # ── PII ───────────────────────────────────────────────────────────────────
    "email": r"[\w.\-]+@[\w.\-]+\.\w{2,}",
    "cpf": r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",
    "cnpj": r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b",
    # ── Infrastructure ────────────────────────────────────────────────────────
    "ip_address": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "aws_s3_url": r"[A-Za-z0-9.\-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com",
}

assert set(PATTERNS) == set(PATTERN_CATEGORY), (
    f"Mismatch: {set(PATTERNS) ^ set(PATTERN_CATEGORY)}"
)

# ── False-positive filters ────────────────────────────────────────────────────

_BEARER_PLACEHOLDER = re.compile(r'^[Xx\-]{10,}$')

_BASIC_HAS_ENTROPY = re.compile(r'[0-9+/=]')  # real base64 always has these
_BASIC_SCREAMING = re.compile(r'^[A-Z][A-Z0-9_]{9,}$')  # BASE_64_ENCODED etc.

_EMAIL_BAD_DOMAIN = re.compile(
    r'(?i)\b(example|test|domain|email|company|your|sample|foo|bar|acme|dummy|mail)\b'
)
_EMAIL_BAD_LOCAL = re.compile(
    r'(?i)^(john\.doe|jane\.doe|user|email|test|sample|you|admin|name|your|noreply|no-reply)'
)

_PRIVATE_IP = re.compile(
    r'^(?:'
    r'127\.'                          # loopback
    r'|10\.'                          # RFC 1918
    r'|192\.168\.'                    # RFC 1918
    r'|172\.(?:1[6-9]|2\d|3[01])\.'  # RFC 1918
    r'|169\.254\.'                    # link-local
    r'|0\.'                           # "this" network / reserved
    r'|255\.'                         # broadcast
    r')'
)

_CPF_UNIFORM = re.compile(r'^(\d)\1{10}$')  # 00000000000, 11111111111 …


def _is_false_positive(name: str, value: str) -> bool:
    """Return True if the match is a known false positive that should be dropped."""

    if name == "authorization_bearer":
        token = value.split(None, 1)[1] if ' ' in value else value
        if _BEARER_PLACEHOLDER.match(token):
            return True

    elif name == "authorization_basic":
        token = value.split(None, 1)[1] if ' ' in value else value
        if not _BASIC_HAS_ENTROPY.search(token):  # plain English word, no digits/base64
            return True
        if _BASIC_SCREAMING.match(token):          # SCREAMING_SNAKE placeholder
            return True

    elif name == "email":
        local, _, domain = value.partition("@")
        if _EMAIL_BAD_DOMAIN.search(domain):
            return True
        if _EMAIL_BAD_LOCAL.match(local):
            return True
        if re.match(r'^x+$', local, re.I):        # xxxxxxxx@xxx.xxx
            return True
        if len(local) <= 1:                        # 1@1.com
            return True

    elif name == "ip_address":
        if _PRIVATE_IP.match(value):
            return True
        # All single-digit octets → version number (2.4.2.0) or docs IP (1.1.1.1)
        if all(len(o) == 1 for o in value.split(".")):
            return True

    elif name in ("generic_api_key", "generic_secret_key", "possible_password"):
        m = re.search(r'[=:]["\' `]*\s*(\S+)', value)
        token = (m.group(1).strip("\"' `") if m else "").rstrip("\\n")
        if re.match(r'(?i)^your[_\-A-Za-z]*$', token):   # YOUR_api_key
            return True
        if re.match(r'^[<\[{$%]', token):                 # <KEY>, ${VAR}, %VAR%
            return True

    elif name == "cpf":
        digits = re.sub(r'\D', '', value)
        if _CPF_UNIFORM.match(digits):          # 000…, 111… etc.
            return True
        if digits.startswith('123456789'):       # 123.456.789-XX
            return True

    return False


def scan_text(text: str) -> list[dict]:
    """Return all pattern matches in text with category. Each dict: pattern_name, matched_value, category."""
    matches = []
    seen_in_run: set[tuple] = set()
    for line in text.splitlines():
        for name, pattern in PATTERNS.items():
            try:
                m = re.search(pattern, line)
                if m:
                    value = m.group()
                    if _is_false_positive(name, value):
                        continue
                    key = (name, value[:40])
                    if key not in seen_in_run:
                        seen_in_run.add(key)
                        matches.append({
                            "pattern_name": name,
                            "matched_value": value,
                            "category": PATTERN_CATEGORY.get(name, "credential"),
                        })
            except re.error:
                pass
    return matches
