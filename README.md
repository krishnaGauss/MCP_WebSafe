# GEO Shield MCP

[![npm](https://img.shields.io/npm/v/geo-shield-mcp)](https://www.npmjs.com/package/geo-shield-mcp) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A defensive, read-only MCP server that lets AI agents (Claude, Gemini CLI, Cursor, VS Code Copilot, Codex and others) inspect websites for manipulation aimed at search engines and **AI assistants**: sneaky and open redirects, hidden text and links, injected spam, hijacked metadata, hidden prompt-injection text, and "Summarise with AI" links whose prefilled prompts try to plant instructions in a visitor's assistant ("AI recommendation poisoning").

Every finding is produced by a deterministic rule and backed by evidence: location, visibility state, an excerpt, severity and confidence (kept separate), remediation, and false-positive notes. Scanned content is always treated as untrusted data.

> **Status: 0.2.0.** `geo_scan_url`, `geo_trace_redirects` and `geo_get_report` are implemented and tested, including detection of invisible-Unicode smuggling and obfuscated or encoded AI instructions. See [Pending](#pending) for later phases.

## Install

Requires **Node.js ≥ 22.12** (it uses the built-in `node:sqlite`). No API keys are needed. Every client below runs the same command: `npx -y geo-shield-mcp`.

### Claude Code

```bash
claude mcp add geo-shield -s user -- npx -y geo-shield-mcp
```

### Gemini CLI

```bash
gemini mcp add geo-shield npx -y geo-shield-mcp
```

### OpenAI Codex CLI

```bash
codex mcp add geo-shield -- npx -y geo-shield-mcp
```

### Claude Desktop, Cursor, Windsurf, Antigravity

These clients use the same JSON shape:

| Client | Config file |
|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows) |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Antigravity | `~/.gemini/antigravity/mcp_config.json` |

```json
{
  "mcpServers": {
    "geo-shield": {
      "command": "npx",
      "args": ["-y", "geo-shield-mcp"]
    }
  }
}
```

### VS Code (GitHub Copilot agent mode)

`.vscode/mcp.json`:

```json
{
  "servers": {
    "geo-shield": { "type": "stdio", "command": "npx", "args": ["-y", "geo-shield-mcp"] }
  }
}
```

### ChatGPT and other web apps

Web apps such as ChatGPT can only connect to **remote** MCP servers over HTTPS. This release runs locally over stdio, so it works with the desktop, CLI and IDE agents above. A hosted HTTP version is planned.

### From source

```bash
git clone https://github.com/krishnaGauss/MCP_WebSafe.git && cd MCP_WebSafe && npm install && npm run build
```

Then point your client at `node /absolute/path/to/MCP_WebSafe/dist/index.js` instead of `npx -y geo-shield-mcp`.

## Usage

Ask your agent in plain language:

- *"Scan https://example.com with geo_scan_url and explain anything suspicious."*
- *"Trace where this link really goes: https://…"*
- *"Check https://… for hidden AI prompt injection."* (or run the `investigate_ai_injection` prompt)
- *"Scan it again as a mobile browser and as a search crawler. Does the content change?"*
- *"Give me the full markdown report for scan_…"*

Scans are stored locally in `~/.geo-shield/geo-shield.db` and purged after 30 days by default.

## Tools

| Tool | What it does |
|---|---|
| `geo_scan_url` | Fetches one URL (SSRF-protected, no JS execution), reconstructs redirects, runs all rules. Inputs: `url`, `scan_profile` (`quick`/`standard`/`deep`), `check_redirects`, `check_hidden_content`, `check_ai_injection`, `render_javascript` (not yet supported — returns a notice), `request_context`. |
| `geo_trace_redirects` | Hop-by-hop redirect chain (3xx + `Refresh`), each hop re-validated; reports declared meta/JS redirects on the final page. Inputs: `url`, `max_redirects`, `request_context`. |
| `geo_get_report` | Full stored report as `markdown` or `json`. |

Request contexts: `desktop_browser`, `mobile_browser`, `search_referrer`, `crawler_ua_simulated`. Non-browser contexts are labelled as **simulations**. A request from this machine is not proof of what a real crawler sees.

**Resources:** `geo://taxonomy`, `geo://rules`, `geo://rules/{rule_id}`, `geo://scan/{scan_id}`, `geo://domain/{domain}/history`
**Prompts:** `investigate_redirect`, `investigate_ai_injection`, `review_scan_findings`

## Rules

| Category | Rules |
|---|---|
| Redirects / cloaking | RED-001 cross-domain redirect · RED-002 open-redirect observed · RED-003 on-page redirect endpoint with external target · RED-004 meta-refresh/JS navigation off-site · RED-005 loop · RED-006 link text shows a different domain · RED-007 HTTPS→HTTP · RED-008 referrer/UA-conditional JS redirect |
| Hidden content | HID-001 hidden text · HID-002 hidden external links · HID-003 off-screen · HID-004 same-colour text · HID-005 tiny/zero-size · HID-006 bidi override in left-to-right text |
| Spam / integrity | SPM-001 spam-keyword outbound links · SPM-002 hidden/unexpected iframe · SPM-003 obfuscated inline script · MET-001 spam keywords in title/metadata · MET-002 cross-domain canonical |
| AI context | AI-001 hidden AI instructions · AI-002 instructions in comments/attributes/meta/JSON-LD · AI-003 instructions in visible text · AI-004 manipulative AI-assistant prefill link · AI-005 benign prefill link (info) · AI-006 unverifiable AI endorsement claims |
| Obfuscation (0.2.0) | AI-007 text smuggled in invisible Unicode (tag characters, variation selectors, zero-width binary) · AI-008 instructions hidden by look-alike letters, fullwidth, leetspeak, spaced letters, invisible characters or right-to-left reversal · AI-009 base64/hex/percent/JS-escaped payloads that decode to instructions or spam |

Full definitions (detection logic, severity mapping, remediation, false positives) are served at `geo://rules`.

**How false positives are kept down:**
- Hidden elements that match accessibility or UI patterns (sr-only, `<details>`, menus, tabs, modals, `aria-controls` targets, camelCase component classes) are counted but not flagged, unless they contain spam keywords, AI instructions or external links.
- Text hidden by a UI toggle (`display:none`, `opacity:0`, `hidden`) is informational unless its content is suspicious.
- Same-colour checks use the colour the text actually inherits, and are marked "unconfirmed" when no background is declared or the text sits next to an image.
- AI-instruction patterns work in families (override, persistence, exfiltration, suppression, recommendation, AI-address). Visible text needs corroborating families before it is flagged.
- De-obfuscation is used only for matching; reports show the original text. Look-alike letters are folded only inside words that mix Latin with another script, or inside mostly-Latin text, so ordinary Russian, Greek or Armenian text is never rewritten. Emoji flags and sequences, presentation selectors, ZWJ/ZWNJ in Persian and Indic scripts, and direction marks in right-to-left text are recognised as legitimate.
- Encoded blobs are reported only when their decoded text matches instruction or spam patterns. `data:` URIs, JWTs, hashes, nonces, images, fonts and archives are skipped.

## Security design

- **SSRF:** only http/https on ports 80/443 (add more with `GEO_SHIELD_ALLOWED_PORTS`). The scanner blocks:
  - credentials embedded in URLs
  - `localhost`, `*.internal`, `*.local` and single-label hostnames
  - IP literals in any encoding (decimal, hex, octal)
  - private, loopback, link-local, CGNAT and metadata ranges, for both IPv4 and IPv6 (including IPv4-mapped addresses)
- **DNS rebinding:** a guarded lookup inside the HTTP connector validates *every* resolved address at connect time, so the address it checks is the address it connects to.
- **Redirects:** followed manually and re-validated on every hop, with loop detection, a timeout, and a body cap (oversized bodies are truncated and flagged).
- **No execution:** scripts are never run, and links and "Summarise with AI" buttons are inspected statically, never followed.
- **Untrusted output:**
  - Every string in a report and every tool result is stripped of invisible characters (controls, zero-width and bidi characters, Unicode tag characters, variation selectors, private-use and lone surrogates), so a scanned page cannot smuggle hidden instructions to the agent through GEO Shield's own output. Decoded hidden text is shown as visible text, with the original code points listed as `U+…` notation.
  - The markdown report wraps excerpts in code spans they can't break out of.
  - Every tool result carries an untrusted-content notice.
- **Privacy and logging:** `Set-Cookie` values are never stored, and logs go to stderr only.
- **Fixture mode** (`GEO_SHIELD_FIXTURE_ALLOW=host:port,...`) is the only way to reach loopback. It's for tests only and logs a warning when set.

## Configuration

See [.env.example](.env.example): `GEO_SHIELD_DB_PATH`, `GEO_SHIELD_LOG_LEVEL`, `GEO_SHIELD_FETCH_TIMEOUT_MS`, `GEO_SHIELD_MAX_BODY_BYTES`, `GEO_SHIELD_ALLOWED_PORTS`, `GEO_SHIELD_RETENTION_DAYS` (stored scans older than this are purged at startup), and `GEO_SHIELD_FIXTURE_ALLOW`.

## Development

```bash
npm test
```

```bash
npm run lint && npm run typecheck
```

```bash
npm run build && npm run demo -- https://example.com
```

- `npm run demo` starts the local fixture site, launches the built server over real stdio as Claude would, and calls every tool.
- `npm run fixtures` runs the fixture site on its own, for use with `npm run inspect` (MCP Inspector).

The tests cover:
- 14+ fixture pages: clean, legitimate hidden UI, screen-reader text, white-on-white links, off-screen text, open redirect, UA- and referrer-conditional redirects, injected casino link, hidden iframe, hidden AI instructions, malicious "Summarise with AI" links, a hijacked spam page, a legitimate migration redirect, an article *about* prompt injection, and more
- SSRF bypass attempts
- unit tests for each rule
- an end-to-end MCP client/server test

### Releasing

Releases are published by [`.github/workflows/release.yml`](.github/workflows/release.yml) when a GitHub Release is published. It runs type-check, lint, tests and build, checks that the release tag equals `v` + the `package.json` version, publishes to npm with provenance through npm trusted publishing (no `NPM_TOKEN`), waits until npm serves the new version, then publishes `server.json` to the MCP Registry with `mcp-publisher login github-oidc`. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the same checks on pull requests and pushes to `main`.

1. Bump the version in `package.json`, `server.json` (`version` and `packages[0].version`) and `SERVER_INFO` in `src/mcp/server.ts`, and add a `CHANGELOG.md` entry. A test fails if the versions disagree.
2. Open a PR, wait for CI, and merge it into `main`.
3. Create a GitHub Release on `main` with tag `vX.Y.Z` (for example `v0.2.0`), either in the GitHub UI or with:
   ```bash
   gh release create v0.2.0 --target main --title v0.2.0 --generate-notes
   ```
   Publishing the release starts the workflow. If the MCP Registry step fails, re-run the workflow: steps that already succeeded (npm publish, registry publish) are skipped.

Prerelease versions (`X.Y.Z-beta.1`) are published to npm under the `next` dist-tag.

#### One-time setup (npm trusted publisher)

The workflow needs npm to trust it before its first run. On [npmjs.com](https://www.npmjs.com/package/geo-shield-mcp), signed in as the package owner:

1. Open **geo-shield-mcp → Settings → Trusted publishing** and choose **GitHub Actions** under "Select your publisher".
2. Fill in:
   - **Organization or user:** `krishnaGauss`
   - **Repository:** `MCP_WebSafe`
   - **Workflow filename:** `release.yml` (the filename only, not the path)
   - **Environment name:** leave empty
   - **Allowed actions:** tick **npm publish**. New trusted publishers only allow `npm stage publish` by default, and the workflow uses `npm publish`.
3. Save. A new trusted publisher expires if it isn't used for a successful publish within 2 days, so add it shortly before the first release. If it expires, delete it and add it again.
4. Optional, once a release has gone through: under **Settings → Publishing access**, choose "Require two-factor authentication and disallow tokens". Trusted publishing keeps working, and manual `npm publish` with 2FA still works.

The MCP Registry needs no setup: `io.github.krishnaGauss/*` names are authorised by the GitHub OIDC token of a workflow in a `krishnaGauss` repository.

To publish by hand instead (needs npm 2FA in the browser): `npm publish` (`prepublishOnly` runs the checks), wait until `npm view geo-shield-mcp@X.Y.Z` shows the version, then `mcp-publisher login github && mcp-publisher publish`.

## Architecture

```
src/
  index.ts                  STDIO entry (serveStdio)
  mcp/                      tools, resources, prompts (transport layer only)
  scanner/orchestrator.ts   pipeline: validate → fetch → parse → detect → score → persist
  scanner/safe-fetch.ts     manual redirects, size/time limits, guarded DNS
  security/                 SSRF policy
  analysis/                 HTML parser, static visibility engine, keyword + AI-instruction patterns
  detectors/                redirect-abuse, hidden-content, spam-injection, ai-prompt-injection
  rules/catalog.ts          rule definitions + taxonomy
  risk/                     evidence builder, scoring
  reports/                  markdown renderer
  storage/                  SQLite (scans, pages, findings, redirect_hops)
```

The scanner engine is independent of MCP: `ScanOrchestrator` can be reused by a CLI or CI job.

## Limitations

- **Static analysis only:** no JavaScript rendering, and external stylesheets aren't fetched. Visibility is inferred from inline styles, `<style>` blocks and attributes.
- **Simulated contexts:** request contexts are simulations, not verified crawler behaviour.
- **No baseline yet:** without a stored baseline, a scan can't tell when content was added.
- **Indicators, not verdicts:** findings call for investigation. They aren't proof of intent or of a search-policy violation.
- **No ingestion proof:** a page scan can't show that any AI model ingested or remembered the content.

## Pending

- Phase 3 · `geo_compare_page_variants` (cloaking diff across contexts), Playwright rendering
- Phase 4 · `geo_scan_site` (sitemap + scoped crawl with authorisation), baselines, `geo_diff_baseline`
- Phase 4/5 · `geo_audit_ugc`, `geo_inspect_ai_content` as a focused tool, memory-poisoning consistency checks
- Phase 6 · historical comparison, finding annotations, `geo://domain/{domain}/baseline`
