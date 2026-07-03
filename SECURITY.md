# Security Policy

## Responsible Use

Harppia is intended for defensive security and authorized OSINT monitoring only. Use it only for organizations, brands, domains, and assets that you are allowed to monitor.

Keep operational forks private. Scanner output, reports, deduplication state, and logs can contain sensitive URLs, identifiers, and leaked credential material.

## Handling Findings

Harppia redacts `matched_value` by default and adds `matched_value_hash` for correlation. Treat even redacted outputs as sensitive because source URLs and keywords can still reveal internal context.

Use `--show-secrets` or `HARPPIA_SHOW_SECRETS=1` only for controlled local triage, and avoid committing raw findings to public repositories.

## Reporting Vulnerabilities

If you find a vulnerability in Harppia itself, please open a private security advisory or contact the maintainer through GitHub. Do not include real secrets, third-party leaked credentials, or sensitive scanner output in public issues.

For findings discovered by running Harppia, follow the affected organization's disclosure process. This project does not provide authorization to access, test, rotate, or disclose third-party secrets.
