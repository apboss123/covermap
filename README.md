# CoverMap: Burp Suite Extension

**Pentest coverage mapper for Burp Suite.** It ingests your Burp Logger CSV (or Logger++ JSON) export and tells you what you actually tested vs. the untested OWASP Top 10 attack surface: straight from inside Burp.

Self-contained Jython 2.7 extension. No Python 3 install required.


---

## What it does

For every endpoint in your proxy history it:

- Profiles **methods, parameters, headers, auth posture, status codes, response variance**
- Classifies behavior (`single` / `browse` / `repeater` / `intruder`)
- Scores **coverage 0–100** with a band label (NO COVERAGE → THOROUGH)
- Maps **OWASP Top 10 gaps** with per-parameter attack matrices:
  - SQLi, NoSQL, XSS, SSTI, CmdInj, Traversal/LFI, SSRF, Open Redirect, CRLF, LDAP/XPath, XXE, Mass Assignment, JWT, ViewState, Business Logic / Race, CORS, Header spoofing, File upload, GraphQL abuse, Response tampering / client-side trust
- Tags **endpoint-class-specific tests** (auth, password reset, registration, OTP/2FA, logout, upload, admin, GraphQL, export)
- Writes a **prioritized retest plan**

Outputs: **HTML** (interactive, per-endpoint Mermaid mindmaps), **JSON** (feed to your analyser), **TXT** (per-request retest report with raw HTTP), **Markdown**.

---

## Install

1. Burp Suite - **Settings - Extensions - Python environment** - set **Jython 2.7 standalone JAR** ([download](https://www.jython.org/download)).
2. **Extensions - Installed - Add** - Extension type **Python** - select `covermap_burp.py`.
3. A new **CoverMap** tab appears.

---

## Use

1. Export your testing history:
   - Burp = **Logger** - right-click history - **Save all** - CSV (default), **or**
   - [Logger++](https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81)  **Export** - JSON.
2. In the CoverMap tab:
   - **Scope (hosts)** - comma-separated, e.g. `app.target.com,*.target.com`. Filters requests **and** names the output dir.
   - **Engagement name** - appears in the report header.
   - **Output base dir** - Browse to pick.
   - Pick **HTML / JSON / TXT / Markdown** formats.
   - **Upload CSV** and/or **Upload JSON** (multi-select supported; mix freely).
   - **Run Analysis**.
3. Reports land in `<base>/<scope>_coverage_<timestamp>/` - click **Open output folder**.

---

## Filters

- **Static-asset filter** (default on): drops `.js/.css/.png/...`
- **Noise-path denylist** (default on): Incapsula, cdn-cgi, Akamai, analytics, telemetry, pixel, recaptcha, etc.
- **Extra exclude paths** — comma-separated substrings.

---

## Output formats

| Format | Filename | Use for |
|---|---|---|
| HTML | `<scope>_audit.html` | Read in browser; per-endpoint Mermaid mindmaps + gap list |
| JSON | `<scope>_audit.json` | Feed to coverage-analyser tooling, SIEM, custom dashboards |
| TXT  | `<scope>_audit.txt`  | Per-request retest plan with reconstructed raw HTTP |
| MD   | `<scope>_audit.md`   | Drop into reports / wiki / PRs |

---

## Screenshots

<img width="959" height="505" alt="tab" src="https://github.com/user-attachments/assets/16da4235-50df-4222-a8de-bb0203eafbf8" />

<img width="959" height="431" alt="tab2" src="https://github.com/user-attachments/assets/c05d77b2-cbb4-45f5-9a34-1f229d41cdb3" />


## How the score works

Coverage starts at 100 and is reduced by:

- **Behavior penalty** — single-hit endpoints lose 60, browsed endpoints lose 30, repeater 0, intruder 5.
- **Real coverage gaps** (auth-removal never tried, methods never tested, no response variance, etc.) — weighted by severity.
- **Recommended attack tests** — capped aggregate penalty so scores stay comparable.

Bands: `0–19 NO COVERAGE` · `20–39 POOR` · `40–59 PARTIAL` · `60–79 MODERATE` · `80–94 ADEQUATE` · `95–100 THOROUGH`.

---

## Why

Most coverage gaps die in the diff between "I clicked around" and "I actually fuzzed every parameter for every class." This extension makes the gap obvious — and points at exactly which payloads to send next.

---

## License

MIT — see [LICENSE](LICENSE).

##

Author: Aditya Patil (https://www.linkedin.com/in/aditya-patil-109690157/), (https://x.com/AadityaPatil_)

