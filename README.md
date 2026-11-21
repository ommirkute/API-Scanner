# API Scanner

Unauthenticated API exposure assessment tool. Scans API endpoints for unauthenticated data access, information disclosure in error bodies, WAF bypass potential, and credential-gating detection. Fail-closed by default — every response is inspected before being marked safe.

Intended for authorized security testing of systems you own or have explicit written permission to test.

## Features

### Core Scanning
- **6-method probe**: GET, POST, PUT, PATCH, DELETE, OPTIONS (HEAD excluded — it hangs on some gateways; add it back via `--methods` if required)
- **Two-tier WAF-aware classification**: vendor-specific strong signatures (Imperva, Akamai, Cloudflare, Sucuri, AWS WAF, Fortinet, etc.) are matched against every 2xx body; generic weak words (proxy, firewall, access denied) are matched only against HTML block pages. A 200 JSON payload containing `{"proxy": "10.0.0.1"}` is data, not a WAF block — no false "Safe" verdicts
- **Fail-closed 4xx/5xx scanning** (`--fail-closed`): All error bodies scanned for stack traces, SQL fragments, framework names, PII, secrets, version banners, DB drivers, and API parameter contracts
- **400 leak scanning**: Validation errors that disclose parameter names ("missing field: customerId") are flagged as `Unsafe (leak)`
- **Content-type-aware parsing**: Correctly classifies JSON, XML/SOAP, form-urlencoded, HTML, and binary responses
- **Credential-gate detection**: Recognizes endpoints that return HTTP 200 with auth error messages ("User Id is required", "Missing Credentials") instead of 401 — marked `Safe (auth-gated)`
- **Live workbook updates**: rows are appended to the Live Scan sheet as each probe completes (thread-safe callback), so the workbook can be opened during the scan and validated in real time
- **TCP precheck** (`--precheck`): detects dead-TCP hosts (DNS resolves but port 443 is closed) before the full scan, preventing multi-hour stalls; unreachable URLs are written out and still appear as grey N/A rows

### WAF Bypass Battery
- **6 standard variants**: GET/POST with browser and scanner User-Agents, POST with `X-HTTP-Method-Override: GET`, OPTIONS enumeration
- **8 path-traversal/encoding variants** for `/admin` paths:
  - `/admin/d/..` — directory traversal
  - `/admin/%2e%2e/..` — URL-encoded dots
  - `/admin/..;/` — IIS/ASP.NET semicolon bypass
  - `/admin/.;/` — dot-semicolon
  - `/admin/ADMIN/../` — mixed case
  - Double URL encoding
  - Trailing dot (`/.`)
  - Semicolon parameter confusion (`;`)
- Per-variant classification: `DATA / TRIV / AUTH / WAF / NODATA / ERR`
- Endpoint verdict: `UNSAFE` if any variant returned DATA, `REVIEW-ERR` if all variants errored, else `SAFE`

## Installation

```bash
# Python 3.9+
pip install requests openpyxl
```

## Quick Start

```bash
# Scan from a text file (one URL per line)
python3 run_scan.py endpoints.txt -o results.xlsx

# Scan from an inventory workbook (.xlsx with a URL column)
python3 run_scan.py inventory.xlsx -o results.xlsx

# With fail-closed policy (recommended for thorough assessments)
python3 run_scan.py endpoints.txt -o results.xlsx --fail-closed

# With TCP precheck (catches dead hosts before scanning)
python3 run_scan.py endpoints.txt -o results.xlsx --precheck

# WAF bypass battery on the scan results
python3 run_bypass.py results.raw.json -o bypass.json

# Build the complete report workbook
python3 run_report.py results.raw.json -o results.xlsx --fail-closed
```

## CLI Reference

### `run_scan.py` — Main Scanner
```
python3 run_scan.py ENDPOINTS [-o OUTPUT] [OPTIONS]

Positional:
  ENDPOINTS           Input: .txt file (one URL per line) or .xlsx inventory

Options:
  -o, --output        Output workbook path (default: api_scan_results.xlsx)
  --url-col           For .xlsx: substring of URL column header (auto-detected)
  --sheet             Result sheet name (default: Result)
  --methods           Comma-separated methods (default: GET,POST,PUT,PATCH,DELETE,OPTIONS)
  -w, --workers       Concurrent probe threads (default: 16)
  -t, --timeout       Per-request timeout in seconds (default: 25)
  --rescan            Force fresh scan, ignoring cache
  --from-cache        Skip network, re-render from raw cache
  --precheck          TCP precheck; write unreachable URLs to a .txt file
  --fail-closed       Scan 4xx/5xx/400 bodies for leaks (fail-closed policy)
  --no-live-sheet     Disable live-updating workbook during scan
  --flush-every N     Flush Live Scan workbook every N completions (default: 50)
  --flush-interval S  Flush Live Scan workbook every S seconds (default: 30)
```

### `run_bypass.py` — WAF Bypass Battery
```
python3 run_bypass.py RAW_JSON [-o OUTPUT] [OPTIONS]

Positional:
  RAW_JSON            Raw scan JSON (*.raw.json from run_scan.py)

Options:
  -o, --output        Output JSON path (default: waf_bypass.json)
  -t, --timeout       Per-request timeout in seconds (default: 20)
  -w, --workers       Concurrent bypass threads, capped at 8 (default: 8)
  --no-traversal      Disable path-traversal variants
  --prefilter MOD:FNC Custom prefilter (module:function returning bool)
```

### `run_report.py` — Report Builder
```
python3 run_report.py RAW_JSON -o OUTPUT [OPTIONS]

Positional:
  RAW_JSON            Raw scan JSON

Options:
  -o, --output        Output workbook (required)
  --endpoints         Endpoints list (.txt or .xlsx) for the API List sheet
  --methods           Method list used in the scan
  --unreachable       File of unreachable endpoint URLs (-> N/A rows)
  --bypass            WAF bypass results JSON (adds Deep Dive block D)
  --inventory         Inventory name shown in sheet headers
  --fail-closed       Set if the scan used --fail-closed
```

## Typical Workflow

```bash
# 1. Scan
python3 run_scan.py my_inventory.xlsx -o results.xlsx --precheck --fail-closed

# 2. WAF bypass on WAF-blocked endpoints
python3 run_bypass.py results.raw.json -o bypass.json

# 3. Final report (all sheets)
python3 run_report.py results.raw.json -o report.xlsx \
    --endpoints my_inventory.xlsx \
    --unreachable results_unreachable.txt \
    --bypass bypass.json \
    --inventory my_inventory.xlsx \
    --fail-closed
```

## Architecture

```
api_scanner/
  __init__.py         Package exports (public API)
  utils.py            Shared constants (WAF markers, leak patterns, credential
                      gates, health regex) + helpers (sanitize, api_path,
                      body parsing, error typing, snippets)
  classifiers.py      Classification logic
                      - classify()          single result -> (verdict, remark)
                      - classify_endpoint() full method map -> (verdict, sublabel,
                        evidence, leaks, data_samples)
  scanner.py          Core scan engine
                      - load_endpoints / load_endpoints_xlsx
                      - tcp_precheck        TCP reachability gate
                      - probe               single (endpoint, method) probe
                      - scan                thread-pool scan + progress
                      - consolidate         per-method -> one output row
                      - LiveWorkbookWriter  real-time Excel appender
  waf_bypass.py       WAF bypass battery
                      - path_traversal_variants  traversal/encoding variants
                      - test_endpoint       6 standard + N traversal variants
                      - run_bypass_battery  orchestrate across endpoints
  reporter.py         Complete workbook builder
                      - API List, Result, Deep Dive, ConfirmedFindings, Summary
```

### Data Flow

```
Input (txt/xlsx)
    |
    v
[TCP Precheck] ---> <stem>_unreachable.txt (N/A rows)
    |
    v
[Scan: probe x methods] ----> <stem>.raw.json (cache)
    |                              |
    |   [Live Scan sheet grows in real time]
    |
    v
[Consolidate] --> per-endpoint rows --> Result sheet
    |
    v
[WAF Bypass Battery] --> <stem>_bypass.json
    |
    v
[Reporter] --> final workbook with all sheets
```

### Public API (Python)

```python
import api_scanner

eps = api_scanner.load_endpoints('endpoints.txt')
result = api_scanner.probe(sess, 'https://host/api/path', 'GET', timeout=25)
verdict, remark = api_scanner.classify('/api/path', 200, 500, False,
                                       'GET', b'{...}', fail_closed=True)
verdict, sublabel, evidence, leaks, data = \
    api_scanner.classify_endpoint(url, method_map)
variants = api_scanner.path_traversal_variants('https://host/admin/api/users')
results = api_scanner.run_bypass_battery('scan.raw.json', 'bypass.json')
```

## Classification Rules

### Verdicts

| Verdict | Meaning |
|---|---|
| `Unsafe (data)` | Non-WAF 2xx with a non-trivial data payload, no credentials |
| `Unsafe (leak)` | Error body (4xx/5xx/400) discloses internals: SQL, stack traces, framework names, PII, secrets, API parameter contracts |
| `Unsafe (suspected)` | Mixed signals: WAF block on some methods, no clean auth on others |
| `Unsafe (unverified-error)` | All methods errored/timed out; safety could not be confirmed |
| `Safe (auth-gated)` | HTTP 200 with a credential-gate message — no data without valid credentials |
| `Safe (auth enforced)` | HTTP 401/403 |
| `Safe (WAF block)` | 2xx with a WAF block-page signature — not data |
| `Safe (trivial)` | Empty / flag-only response (`{}`, `pong`, `{"success":true}`) |
| `Safe (not found)` | HTTP 404 |
| `Safe (method blocked)` | HTTP 405 |
| `N/A (unreachable)` | Host not reachable from the test position |

### Fail-Closed Scanning (`--fail-closed`)
All 4xx/5xx/400 bodies are scanned for:
1. Stack traces (`Traceback`, `at com.`, `caused by`, `File "...", line`)
2. SQL disclosure (`SELECT ... FROM`, `SQLSTATE`, `jdbc:`, DB product names)
3. Framework disclosure (Hibernate, Spring, Django, Express, etc.)
4. PII (email addresses, structured email fields)
5. Secrets (password/secret/bearer tokens, API keys)
6. Version banners / infra disclosure (product and framework names)
7. API parameter contracts (400 bodies naming required/missing fields)

### Credential-Gate Phrases
2xx bodies containing these are marked `Safe (auth-gated)`: "User Id is required", "Password is required", "Missing Credentials", "API authentication failed", "Authentication required", "Authorization required", "Token is required", "Login required", "Access denied", "Not authorized", "Forbidden", "Invalid credentials", "Session expired/invalid/required".

### Trivial-Body Detection
A body is trivial (no data) when: empty/null; flag-only JSON envelopes (`{}`, `{"success":true}`, ≤4 keys with only null/bool/short values); SOAP Envelope with a single Fault/Status node; form data with only trivial key=value pairs; or a known health response on a health path (`/ping`, `/health`, `/livez`, …). Values that look like PII (email) or IDs (6+ consecutive digits) are **not** trivial — they get flagged for review.

## Output Workbook Sheets

| Sheet | Contents |
|---|---|
| `API List` | Every input endpoint (deduped) — verify 0 missing / 0 extra |
| `Result` | 8 columns: `FQDN \| API \| Method \| Status Code \| length \| Safe / unsafe \| remark \| evidence`. Red = Unsafe, green = Safe, grey = N/A. One row per endpoint (Method = ALL), per-method detail in `evidence` |
| `Live Scan` | Real-time progress log (timestamp, host, path, method, status, length, content-type, body snippet). Rows appear while the scan runs |
| `Deep Dive` | Block A: per-host response-class breakdown. Block B: review candidates. Block C: leak-suspect error bodies. Block D: WAF-bypass results (when provided). Empty candidate lists are documented as NONE, never omitted |
| `ConfirmedFindings` | Ranked findings with full curl request + response per method for manual verification |
| `Summary` | Totals: endpoints tested vs N/A, verdict counts, fail-closed mode |

## CORS Policy
CORS misconfiguration (ACAO=`*` or reflected origin + credentials) is **not** reported as an Unsafe finding. CORS headers are captured in the evidence column for reference only. If an endpoint independently returns genuine unauthenticated data, the data is the finding; the CORS header is incidental.

## Known Limitations
1. **Intranet-only hosts** cannot be tested without internal network access — they are marked N/A, never "Safe".
2. **WAF bypass is bounded**: traversal variants target `/admin` paths specifically; other techniques need manual testing.
3. **No credential spraying**: the tool does not try valid credential pairs against auth-gated endpoints.
4. **Response body cap**: bodies are truncated in evidence columns (400 chars) and ConfirmedFindings (5000 chars); the full cache lives in the `.raw.json` file.
5. **Write methods** send an empty `{}` JSON body to limit blast radius on open write endpoints.

## Responsible Use
This tool is for authorized testing only. Before scanning any system you do not own:
- obtain written permission (scope, time window, and method restrictions),
- prefer read-only probes,
- do not exfiltrate bulk data or PII — confirm data returns, record the finding, stop,
- keep request rates modest (`-w`) to avoid triggering rate limits or service disruption.

## License
MIT
