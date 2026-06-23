# Security Review — Analyst Toolkit v2.0

**Date:** June 18, 2026
**Application:** Analyst Toolkit v2.0 (formerly ThreatAnalyzer)
**Deployment:** phishguard-plum.vercel.app
**Authentication:** HTTP Basic Auth (middleware.ts)
**Stack:** Next.js 16, TypeScript, Tailwind CSS

---

## 1. Does the tool execute fetched content or only analyze/display it?

**Analyze-only. The tool never executes fetched content.**

- **URL Scan:** Sends the URL to VirusTotal and URLhaus APIs for reputation lookups. The URL itself is never rendered in an iframe or opened in a browser. Results are displayed as JSON data.
- **OSINT (Firecrawl):** Sends target URL to Firecrawl API which returns markdown text. This markdown is displayed in a `<pre>` tag — never rendered as HTML or injected into the DOM. No scripts from scraped content are executed.
- **Redirect Tracer:** Uses `fetch()` with `redirect: 'manual'` to follow HTTP redirects at the network level. The destination page content is never rendered — only HTTP status codes and headers are extracted.
- **QR Code:** Uses `jsQR` library to decode QR images client-side via Canvas pixel analysis. The decoded URL is passed to the URL Scan API — never opened or navigated to.
- **Email analysis:** Parses raw email text for headers, keywords, and URLs. No email content is rendered as HTML. URLs are extracted as plain text strings.

**Summary:** All fetched data is treated as untrusted text. It is parsed, displayed in sanitized React components, and never executed.

---

## 2. Where are API keys stored?

**Environment variables only. No keys in source code.**

| Key | Location | Required |
|-----|----------|----------|
| `VIRUSTOTAL_API_KEY` | Vercel env var / `.env` (gitignored) | Yes — Hash + URL scan |
| `FIRECRAWL_API_KEY` | Vercel env var / `.env` (gitignored) | No — OSINT works on free tier without key |

- `.env` is in `.gitignore` (line 34) — never committed
- `.env.example` exists with placeholder values for documentation
- Previous hardcoded VT key has been removed from all source files
- No keys are exposed to the client — all API calls happen server-side in Next.js API routes

---

## 3. Is scanned data persisted, and where/how long?

**Two persistence layers:**

### Client-side (localStorage)
| Data | Key | Lifespan | Purpose |
|------|-----|---------|---------|
| Last analysis result | `threatAnalyzer_lastResult` | Until browser clears | Report generator |
| Scan history (last 50) | `threatAnalyzer_history` | Until browser clears | Overview dashboard |
| Theme preference | `threatAnalyzer_theme` | Until browser clears | UI preference |

**Note:** localStorage is per-browser, per-device. No cross-user data leakage possible.

### Server-side (audit log)
| Data | Location | Format | Retention |
|------|----------|--------|----------|
| Scan audit entries | `data/audit-log.json` (server filesystem) | JSON array | Last 200 entries |

Each audit entry contains: timestamp, tool used, target input, risk score, threat level, MITRE ATT&CK tags, user identifier.

**No raw scan content (URLs, email bodies, file hashes) is stored beyond the audit log metadata.** The actual analysis results are returned to the browser and not persisted server-side.

---

## 4. What input sanitization exists for user-submitted URLs/domains?

| Input | Sanitization |
|-------|-------------|
| URL Scan | Input passed to VirusTotal API (VT handles URL encoding). URL is never used in a database query or command execution. |
| Domain | Domain stripped of `http://`/`https://` prefix, lowercased, path removed. Validated as string type before processing. |
| IP Lookup | Validated against IPv4 regex (4 octets, 0-255 each) before processing. |
| Hash | Validated against MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex) regex patterns. Invalid formats rejected with 400. |
| Email | Sender domain extracted via string split on `@`. Domain validated as string. Raw email content never executed — only regex-extracted for patterns. |
| Bulk Scan | Each line treated as independent input, passed through same sanitization as URL Scan. |

**Key protections:**
- All API routes use `typeof` checks on input parameters
- All fetch calls use `AbortController` with timeouts (4-6s) to prevent hanging
- No user input is ever used in: file paths, database queries, shell commands, or `eval()`
- React's built-in JSX escaping prevents XSS from displayed content
- Scraped markdown content displayed in `<pre>` tags — never as `dangerouslySetInnerHTML`

---

## 5. Authentication

- HTTP Basic Auth via `middleware.ts`
- Credentials stored as Base64 comparison string
- All routes (pages + API) protected — no public endpoints
- No multi-user support yet — single shared credential
- Recommended for production: migrate to OAuth or session-based auth

---

## 6. Network Security

- All external API calls made server-side only
- HTTPS enforced on all external calls (VirusTotal, Firecrawl, crt.sh, RDAP, Google DNS, Shodan)
- No CORS configuration exposing APIs to other origins
- Deployed on Vercel with automatic TLS/SSL

---

## 7. Dependencies

- `jsqr` — client-side QR decoding (no network calls)
- `next` — framework
- `react` — UI library
- No external data persistence libraries (no SQLite, no database drivers)
- No content rendering libraries that could execute untrusted HTML

---

**Reviewed by:** Hermes Agent (automated)
**Reviewer note:** This tool follows analyze-only principles. No fetched content is executed. API keys are environment-variable based. Input sanitization is type-checked and regex-validated. The tool is suitable for CSOC submission with the caveat that Basic Auth should be upgraded for production multi-user environments.