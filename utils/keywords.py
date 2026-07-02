"""
Keyword list for OSINT scanning.

Add the organization names, brand identifiers, and domain fragments you want
to monitor. Keywords are matched case-insensitively against file content,
API spec titles, and gist descriptions across all scanners.

Tips:
  - Prefer specific sub-brand names over generic words to reduce noise.
  - Domain fragments (e.g. "company.com") catch credentials in connection strings.
  - Internal platform names (payment systems, CI tools, internal APIs) surface
    developer configs that brand names alone would miss.
  - Keep this list focused — every keyword multiplies GitHub API calls.
"""

KEYWORDS = [
    # ── Primary targets ────────────────────────────────────────────────────────
    # "target-company",
    # "target-platform",

    # ── Subsidiaries / acquired brands ────────────────────────────────────────
    # "sub-brand",
    # "acquired-company",

    # ── Internal tech platforms ────────────────────────────────────────────────
    # "internal-payment-system",
    # "internal-api-name",

    # ── Legacy / historical brands (often still in prod configs) ───────────────
    # "legacy-brand",

    # ── Domain identifiers (appear in env vars and connection strings) ─────────
    # "target.com",
    # "platform.target.com",

    # ── Financial institutions ─────────────────────────────────────────────────
    # "bank-name",
    # "payment-processor",

    # ── Fintechs / BaaS ────────────────────────────────────────────────────────
    # "fintech-name",
    # "baas-platform",

    # ── E-commerce / marketplaces ─────────────────────────────────────────────
    # "marketplace",
    # "e-commerce-brand",

    # ── Strategic companies / verticals ───────────────────────────────────────
    # "strategic-partner",
    # "acquired-vertical",
]
