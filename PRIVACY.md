# ScamShield Privacy Policy

_Last updated: 2026-08-24_

ScamShield is designed privacy-first. This policy describes exactly what the extension does and does not do.

## What ScamShield stores

- **Settings** (AI toggle, automatic-scan preference, theme) — stored locally in your browser via `chrome.storage.local`.
- **Scan history** (hostname, score, risk level, timestamp; maximum 50 entries) — stored locally on your device only. You can clear it at any time from the History screen.
- Nothing is synced to any cloud service by the extension itself.

## What ScamShield collects

- **With AI Detection OFF (default):** nothing leaves your browser. All analysis is performed locally by deterministic rules.
- **With AI Detection ON:** when you scan a website, the extension sends _minimal security metadata_ to the backend URL you configure in Settings:
  - The page URL and hostname
  - URL structure signals (length, subdomain depth, hyphen count, punycode presence, TLD)
  - Aggregate page-content signal counts (e.g., "a login form exists", number of urgency phrases matched)
  - Redirect-chain metadata (when available)

## What ScamShield never collects

- Passwords or any form-field values
- Cookies, session tokens, or authentication headers
- Payment information
- Full webpage contents
- Browsing history beyond scans you explicitly run (unless automatic scanning is enabled, in which case only the same minimal metadata described above)

## Third-party services

When AI Detection is enabled, your configured backend forwards minimal signals to an AI provider (OpenAI) to generate the analysis. The API key for that provider is held server-side and is never included in the extension. No other third parties receive data, and the extension contains no analytics or tracking.

## Permissions

ScamShield requests only: `activeTab`, `scripting`, `storage`, and `sidePanel`. An optional `webNavigation` permission may be requested for redirect analysis. Each permission's purpose is documented in the README.

## Contact

For questions about this policy, open an issue in the project repository.
