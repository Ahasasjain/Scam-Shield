# ScamShield Privacy Policy

**Last updated:** 2026-10-28

ScamShield is a Chrome extension that looks for scam and phishing indicators on websites. This policy explains what data ScamShield processes, where that data is sent, how long it is kept, and what ScamShield never collects. It applies to the ScamShield extension and the ScamShield backend API.

## The short version

- ScamShield never reads or transmits passwords, one-time passwords, card numbers, CVVs, UPI or bank credentials, cookies, session tokens, or other form-field values.
- On a fresh scan, ScamShield sends the page URL and domain to its backend for threat lookup. The backend may send the URL to Google Safe Browsing.
- ScamShield contacts `rdap.org` to look up domain registration age.
- When local evidence warrants AI analysis, ScamShield sends security metadata to its backend, which sanitizes it before forwarding it to Groq.
- Scan history is stored locally in your browser (up to 50 entries) and can be cleared at any time.
- ScamShield does not sell your data, use it for advertising, or use it for creditworthiness or lending decisions.

## What ScamShield processes

When a scan runs — manually, or automatically if automatic scanning is enabled — ScamShield processes:

- **The page address:** the URL, hostname, registrable domain, whether HTTPS is used, and URL structure such as length, subdomain depth, hyphens, punycode, and TLD.
- **The shape of the page:** whether login, payment, OTP, UPI, or banking fields are present; whether a password field appears on an HTTP page; counts of urgency, giveaway, and fake-warning phrases; hostnames of external scripts; and form-action origins and categories.
- **Redirects:** the redirect-chain length, number of cross-origin hops, and final URL, when you grant the optional `webNavigation` permission.
- **Domain registration:** approximate domain age and registrar from the public RDAP registry, when available.

The content script reads visible page text locally to count heuristic phrases. It does not send the text itself. ScamShield does not read or transmit the values you type into fields, and it does not use keylogging, screen recording, or clipboard access.

## What ScamShield never collects

ScamShield does not collect or transmit:

- passwords, one-time passwords (OTPs), PINs, or authentication codes;
- credit or debit card numbers, CVVs/CVCs, UPI identifiers, bank credentials, or other payment values;
- cookies, session tokens, or authentication headers;
- the contents of form fields;
- full page text or full webpage contents;
- files from your device;
- keystrokes, mouse movements, or clipboard contents;
- precise location, health information, or personal communications;
- your name, email address, phone number, or account credentials.

URLs can contain sensitive information depending on the website. ScamShield processes the current page URL as described below. Scan history stores the URL locally so you can review it; you can clear it at any time. Before sending data to the AI provider, the backend removes query strings and fragments and redacts sensitive path segments.

## Where data is sent

| Recipient | Data | Purpose |
|---|---|---|
| **ScamShield backend** (hosted on Render) | Page URL, hostname, registrable domain, URL structure, page signals, redirect metadata, and domain-age data | Run threat lookup and, when warranted, AI analysis |
| **Google Safe Browsing** | Page URL | Check the URL against Google's threat lists |
| **Groq** | Sanitized URL, URL structure, aggregate page signals, redirect metadata, and domain metadata | Generate AI analysis when local evidence warrants it |
| **RDAP.org** | Registrable domain | Look up domain registration age and registrar |

The backend downloads public threat feeds (including OpenPhish) but does not send your URL to those feeds. ScamShield contains no analytics, advertising, or third-party tracking SDKs.

The backend uses Google Safe Browsing when it is configured. If no threat provider returns a result, ScamShield reports the lookup as unavailable; it never treats a provider outage as evidence that a site is safe.

### AI analysis

AI analysis is an additional signal, not the detector. ScamShield requests it automatically when local evidence matches its AI-trigger rules — for example, a lookalike domain, a cross-origin password form, or a request for an OTP or card security code. There is no separate AI toggle in the current build.

The extension sends the scan context to the ScamShield backend. Before forwarding anything to Groq, the backend:

- removes URL query strings and fragments;
- redacts sensitive path segments such as reset tokens, email addresses, and long opaque identifiers;
- sends only the structural signals described above.

AI output is advisory. It cannot downgrade a confirmed threat-intelligence match or override the deterministic rules.

## What is stored, and for how long

### On your device

- **Settings:** automatic-scan preference and theme, stored in `chrome.storage.local` until you change them or uninstall the extension.
- **Scan history:** up to 50 entries containing the URL, hostname, score, verdict, short evidence titles, analysis mode, and timestamp. Stored in `chrome.storage.local` until you clear it from the History screen or uninstall the extension.
- **Threat-result cache:** URL, verdict, and timestamp for up to 500 entries. Confirmed threats are cached for up to 24 hours; negative results for up to 30 minutes.
- **Redirect-chain data:** when the optional `webNavigation` permission is granted, redirect chains are kept in `chrome.storage.session` and are cleared when the browser session ends.
- **In-memory scan cache:** the background service worker may reuse a recent scan result for up to 5 minutes. This cache is cleared when the service worker restarts.

### On the backend

- **Threat-lookup cache:** in-memory only, keyed by URL and domain, with a maximum of 5,000 entries. Confirmed matches are kept for up to 24 hours, negative results for up to 30 minutes, and unavailable results for up to 60 seconds. The cache is cleared when the backend restarts.
- **No scan database:** the backend does not maintain a persistent database of scans.
- **Hosting logs:** the hosting provider may retain standard request metadata such as IP address, user agent, timestamp, and response status. The application is configured not to log request bodies, and API keys are redacted.
- **AI requests:** processed to generate a response. Groq processes requests under its own terms and privacy policy.

## Permissions

ScamShield requests the following Chrome permissions:

- `activeTab` — scan the tab you invoke the extension on.
- `scripting` — inject the page-signal collector on demand.
- `storage` — store settings, scan history, and short-lived caches locally.
- `sidePanel` — display warnings and analysis in Chrome's side panel.
- Optional `webNavigation` — analyze redirect chains, only if you grant it.
- Host permissions for `http://*/*` and `https://*/*` — scan ordinary web pages. ScamShield does not scan `chrome://`, `file://`, or other browser system pages.

## Limited Use

ScamShield's use of user data complies with the Chrome Web Store User Data Policy, including the Limited Use requirements:

- Data is used only to provide and improve ScamShield's single purpose: detecting scam and phishing websites.
- We do not sell user data.
- We do not use or transfer user data for advertising or for purposes unrelated to that single purpose.
- We do not use or transfer user data to determine creditworthiness or for lending purposes.
- Data is shared only with the service providers listed above, as necessary to provide the analysis. Their handling of data is governed by their own terms and privacy policies.

## Your choices

- **Automatic scanning:** turn it off in Settings. Manual scans still contact the backend for threat lookup.
- **History:** clear scan history at any time from the History screen.
- **Uninstall:** uninstalling the extension removes its local storage.
- **Avoid a lookup:** if you do not want a page URL sent for threat lookup, do not scan that page.
- **Questions or requests:** open an issue at <https://github.com/Ahasasjain/Scam-Shield/issues>. Do not include sensitive information in a public issue.

## Security

ScamShield uses HTTPS for its network requests and rate limits its backend endpoints. API keys for Google Safe Browsing and Groq are stored only in the backend environment and are never included in the extension.

## International processing

The service providers listed above may process data in countries other than your own, including the United States. Their handling of data is governed by their own privacy and security practices.

## Third-party privacy policies

- Google: <https://policies.google.com/privacy>
- Groq: <https://groq.com/privacy-policy>
- RDAP.org: <https://about.rdap.org/>
- Render: <https://render.com/privacy>

## Children

ScamShield is not directed to children under 13, and we do not knowingly collect personal information from children.

## Changes to this policy

We may update this policy as ScamShield changes. The "Last updated" date at the top will change, and material changes will be reflected in the repository and release notes. We encourage you to review this policy periodically.

## Contact

For privacy questions or requests, open an issue at:

<https://github.com/Ahasasjain/Scam-Shield/issues>

Please do not include passwords, tokens, or other sensitive information in a public issue.
