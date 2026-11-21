#!/usr/bin/env python3
"""Excel workbook builder for api_scanner.

Produces the complete result workbook with sheets:
  API List          All input endpoints (dedup check)
  Result            8-column standard format
  Deep Dive         Per-host response-class breakdown + review candidates +
                     leak-suspect error bodies + WAF-bypass block
  ConfirmedFindings Single verified-findings sheet with full curl request/response
  Summary           Per-application + per-host tested vs unreachable counts
"""

import json
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime

import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from .utils import LEAK_PATTERNS, sanitize, param_contract_hints
from .scanner import api_path, consolidate, COLS, COL_W
from .classifiers import classify_endpoint


# ---- Styles ----
_HEAD = PatternFill('solid', fgColor='305496')
_RED = PatternFill('solid', fgColor='FFC7CE')
_AMB = PatternFill('solid', fgColor='FFEB9C')
_GRN = PatternFill('solid', fgColor='C6EFCE')
_GRY = PatternFill('solid', fgColor='D9D9D9')
_WRAP = Alignment(wrap_text=True, vertical='top')


def _hdr(ws, cols, widths):
    """Write header row with styling."""
    ws.append(cols)
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    for c in ws[1]:
        c.fill = _HEAD
        c.font = Font(color='FFFFFF', bold=True)
    ws.freeze_panes = 'A2'


def _curl_string(method, url, headers, body=''):
    """Build a full curl command string for reproduction."""
    parts = [f"curl -k -s -X {method}"]
    for k, v in headers.items():
        parts.append(f"-H '{k}: {v}'")
    if body:
        safe_body = body.replace("'", "'\\''") if "'" in body else body
        parts.append(f"-d '{safe_body}'")
    parts.append(f"'{url}'")
    return ' \\\n    '.join(parts)


def build_workbook(out_path, eps, raw_rows, methods,
                   unreachable_eps=None, bypass_results=None,
                   inventory_name='',
                   sheet_result='Result', fail_closed=False):
    """Build the complete result workbook.

    Args:
        out_path:         Output .xlsx path.
        eps:              List of all input endpoint URLs.
        raw_rows:         Raw per-method scan results (list of dicts).
        methods:          Method list used in scan.
        unreachable_eps:  List of URLs that were unreachable (N/A).
        bypass_results:   Dict of endpoint -> bypass result (from run_bypass_battery).
        inventory_name:   Inventory file name (for sheet headers).
        sheet_result:     Name for the Result sheet.
        fail_closed:      Whether fail-closed scanning was active.
    """
    wb = openpyxl.Workbook()
    now = datetime.now().strftime('%Y-%m-%d %H:%M %Z')

    # ---- API List ----
    api_sheet = wb.active
    api_sheet.title = 'API List'
    api_sheet.append(['Endpoint URL'])
    for ep in sorted(set(eps)):
        api_sheet.append([ep])
    api_sheet.column_dimensions['A'].width = 80
    api_sheet.freeze_panes = 'A2'

    # Build per-endpoint maps
    by_ep = defaultdict(list)
    for r in raw_rows:
        by_ep[r['endpoint']].append(r)

    # ---- Result sheet ----
    rows_out = []

    all_endpoints = list(dict.fromkeys(
        [r['endpoint'] for r in raw_rows] +
        [ep for ep in (unreachable_eps or [])]
    ))

    for ep in all_endpoints:
        rlist = by_ep.get(ep, [])
        if rlist:
            rows_out.extend(consolidate(rlist, methods, fail_closed=fail_closed))
        else:
            # Unreachable — no scan data. ONE N/A row per endpoint (method=ALL).
            fq, api = api_path(ep)
            rows_out.append(dict(
                fqdn=fq, api=api, method='ALL',
                status='ERR', length=0,
                verdict='N/A (unreachable)',
                sublabel='',
                remark=(f'NOT TESTED - host unreachable from test position '
                        f'| all: ' + '; '.join(f'{m}->ERR' for m in methods)),
                evidence='; '.join(f'{m}->ERR DNS/conn' for m in methods),
                url=ep))

    # Apply N/A override (in case an unreachable endpoint somehow has scan data)
    na_set = set(unreachable_eps or [])
    for r in rows_out:
        if r.get('url', '') in na_set:
            r['verdict'] = 'N/A (unreachable)'
            r['remark'] = ('NOT TESTED from current position - intranet-only host / '
                          'host not reachable (no public route). Re-test from a '
                          'position with internal network access. | all: ' +
                          '; '.join(f'{m}->ERR' for m in methods))
            r['evidence'] = '; '.join(f'{m}->ERR DNS/conn' for m in methods)

    out = wb.create_sheet(sheet_result)
    out.append(COLS)

    def mkey(r):
        head = r['method'].split(',')[0].strip()
        return methods.index(head) if head in methods else 99

    order = {'Unsafe': 0, 'Safe': 1, 'N/A': 2}
    all_rows = list(rows_out)
    all_rows.sort(key=lambda r: (
        order.get(r['verdict'].split('(')[0].strip(), 3) if not r['verdict'].startswith('N/A') else 2,
        r['api'], mkey(r)))

    for r in all_rows:
        out.append([sanitize(r.get('fqdn', '')), sanitize(r.get('api', '')),
                    r.get('method', 'ALL'), r.get('status', 'ERR'),
                    r.get('length', 0), r.get('verdict', 'Safe'),
                    sanitize(r.get('remark', '')), sanitize(r.get('evidence', ''))])

    for i, w in enumerate(COL_W, 1):
        out.column_dimensions[get_column_letter(i)].width = w
    for c in out[1]:
        c.fill = _HEAD
        c.font = Font(color='FFFFFF', bold=True)
    for row in out.iter_rows(min_row=2):
        v = str(row[5].value or '')
        fill = _RED if v.startswith('Unsafe') else (_GRY if v.startswith('N/A') else _GRN)
        for c in row:
            c.fill = fill
            if c.column in (7, 8):
                c.alignment = _WRAP
    out.freeze_panes = 'A2'

    # ---- Deep Dive ----
    _build_deep_dive(wb, raw_rows, rows_out, na_set,
                     bypass_results, now, methods)

    # ---- ConfirmedFindings ----
    _build_confirmed_findings(wb, raw_rows, by_ep, methods, fail_closed)

    # ---- Summary ----
    _build_summary(wb, eps, rows_out, na_set, now, inventory_name,
                   fail_closed)

    wb.save(out_path)
    print(f'[+] workbook -> {out_path} ({len(wb.sheetnames)} sheets: {", ".join(wb.sheetnames)})')
    return wb


# ---- Deep Dive ----

def _write_block_header(ws, row, title, cols, widths):
    """Write a section title + column headers. Returns next data row."""
    ws.cell(row=row, column=1, value=title).font = Font(bold=True)
    row += 1
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = max(
            w, ws.column_dimensions[get_column_letter(i)].width or 0)
    for c_i, h in enumerate(cols, 1):
        cell = ws.cell(row=row, column=c_i, value=h)
        cell.fill = _HEAD
        cell.font = Font(color='FFFFFF', bold=True)
    return row + 1


def _build_deep_dive(wb, raw_rows, rows_out, na_set,
                     bypass_results, now, methods):
    if 'Deep Dive' in wb.sheetnames:
        del wb['Deep Dive']
    dd = wb.create_sheet('Deep Dive')
    row = 1

    # Title
    dd.cell(row=row, column=1,
            value=f'DEEP DIVE — API Scanner {now}').font = Font(bold=True, size=12, color='305496')
    row += 1
    dd.cell(row=row, column=1,
            value=('Method: 6-method unauthenticated probe; '
                   'WAF block pages are NOT data; fail-closed scanning on error bodies. '
                   'Exposure indicator = non-WAF 2xx with data payload.'))
    dd.cell(row=row, column=1).font = Font(italic=True, size=9)
    row += 2

    # ---- Block A: Per-host response-class breakdown ----
    row = _write_block_header(dd, row,
        'A. Per-host response-class breakdown (reachable hosts)',
        ['Host', 'Endpoints', 'WAF-block (200)', '401/403', '404', '405',
         '3xx', '2xx-DATA', 'leak-suspect 4xx/5xx', 'ERR', 'Unsafe', 'Verdict'],
        [24, 14, 15, 10, 9, 9, 8, 12, 22, 8, 10, 28])

    host_counter = defaultdict(Counter)
    uniq_eps = defaultdict(set)
    for r in raw_rows:
        h = r['endpoint'].split('/')[2]
        st = r['status']
        if st is None:
            host_counter[h]['ERR'] += 1
        elif r.get('waf'):
            host_counter[h]['WAF-200'] += 1
        elif st == 204:
            host_counter[h]['204'] += 1
        elif 200 <= st < 300:
            if (r.get('length') or 0) > 0:
                host_counter[h]['2xx-DATA'] += 1
            else:
                host_counter[h]['2xx'] += 1
        elif st in (401, 403):
            host_counter[h]['401/403'] += 1
        elif st == 404:
            host_counter[h]['404'] += 1
        elif st == 405:
            host_counter[h]['405'] += 1
        elif 300 <= st < 400:
            host_counter[h]['3xx'] += 1
        elif 400 <= st < 500:
            host_counter[h]['4xx/5xx'] += 1
        elif st >= 500:
            host_counter[h]['4xx/5xx'] += 1
        uniq_eps[h].add(r['endpoint'])

    unsafe_per_host = Counter()
    for r in rows_out:
        if r.get('verdict', '').startswith('Unsafe'):
            h = r.get('url', r.get('fqdn', '')).split('/')[2]
            unsafe_per_host[h] += 1

    leak_by_host = Counter()
    for r in raw_rows:
        if r.get('status') and 400 <= r['status'] < 600:
            btext = str(r.get('body') or '')
            for pat, lbl in LEAK_PATTERNS:
                if re.search(pat, btext, re.I):
                    leak_by_host[r['endpoint'].split('/')[2]] += 1
                    break

    for h in sorted(host_counter, key=lambda x: -len(uniq_eps.get(x, set()))):
        c = host_counter[h]
        exp = c['2xx-DATA']
        leak = leak_by_host.get(h, 0)
        unsafe_n = unsafe_per_host.get(h, 0)
        verdict = 'REVIEW' if (exp > 0 or leak > 0 or unsafe_n > 0) else 'SAFE'
        vals = [h, len(uniq_eps.get(h, set())),
                c['WAF-200'], c['401/403'], c['404'], c['405'],
                c['3xx'], exp, leak, c['ERR'],
                unsafe_n, verdict]
        for cc, v in enumerate(vals, 1):
            cell = dd.cell(row=row, column=cc, value=v)
            if verdict == 'REVIEW' and cc in (8, 9, 11, 12):
                cell.fill = _RED
            elif verdict == 'SAFE':
                cell.fill = _GRN
            else:
                cell.fill = _AMB
        row += 1
    row += 1

    # ---- Block B: Review candidates ----
    review_candidates = []
    by_ep_map = by_ep_from_rows(raw_rows)
    for ep, rlist in by_ep_map.items():
        reasons = []
        has_data = False
        for r in rlist:
            st = r.get('status')
            if st is None or r.get('waf'):
                continue
            if 200 <= st < 300 and (r.get('length') or 0) > 0:
                bt = _body_type(r)
                if not _is_trivial_simple(r.get('body', ''), bt, ep):
                    has_data = True
            if 300 <= st < 400:
                loc = r.get('location', '')
                if re.search(r'/admin|/data|/export|/internal', loc, re.I):
                    reasons.append(f'redirect to sensitive path ({loc[:80]})')
        if has_data:
            reasons.append('non-WAF 2xx with data payload')
        if reasons:
            review_candidates.append((ep, reasons))

    dd.cell(row=row, column=1,
            value=f'B. Review candidates: {len(review_candidates)}'
            ).font = Font(bold=True)
    row += 1

    if review_candidates:
        row = _write_block_header(dd, row,
            '', ['Endpoint', 'Trigger reason', 'Best status', 'Best length',
                 'Body snippet', 'Assessment'],
            [52, 40, 10, 10, 60, 34])

        for ep, reasons in review_candidates[:100]:
            rlist = by_ep_map.get(ep, [])
            best = _best_live_result(rlist)
            body_s = str(best.get('body', ''))[:300]
            leak_tag = [lbl for pat, lbl in LEAK_PATTERNS if re.search(pat, body_s, re.I)]
            if leak_tag:
                body_s = f'[LEAKS: {", ".join(leak_tag)}] ' + body_s
                assess = 'POTENTIAL EXPOSURE — info disclosure'
                fill = _RED
            elif best.get('status') and 200 <= best['status'] < 300 and (best.get('length') or 0) > 0:
                assess = 'POTENTIAL EXPOSURE — unauth data'
                fill = _RED
            else:
                assess = 'auth-enforced / no unauth data'
                fill = _GRN
            vals = [ep, '; '.join(reasons),
                    best.get('status', '-'), best.get('length', 0),
                    body_s, assess]
            for cc, v in enumerate(vals, 1):
                cell = dd.cell(row=row, column=cc, value=v)
                cell.fill = fill
                if cc in (2, 5, 6):
                    cell.alignment = _WRAP
            row += 1
    else:
        dd.cell(row=row, column=1,
                value='NONE — no endpoint returned a non-WAF 2xx with data, '
                      'a leak-suspect error body, or a sensitive redirect. '
                      '0 unauthenticated data exposures found.').fill = _GRN
        for c in range(1, 7):
            dd.cell(row=row, column=c).fill = _GRN
        row += 1
    row += 1

    # ---- Block C: Leak-suspect error bodies ----
    leak_eps = []
    for r in raw_rows:
        if r.get('status') and 400 <= r['status'] < 600:
            btext = str(r.get('body') or '')
            hits = [lbl for pat, lbl in LEAK_PATTERNS if re.search(pat, btext, re.I)]
            if hits:
                leak_eps.append((r['endpoint'], r['method'], r['status'], hits, btext[:200]))

    dd.cell(row=row, column=1,
            value=f'C. Leak-suspect error bodies (4xx/5xx): {len(leak_eps)}'
            ).font = Font(bold=True)
    row += 1

    if leak_eps:
        row = _write_block_header(dd, row, '',
            ['Endpoint', 'Method -> Status', 'Leak signatures', 'Body excerpt'],
            [52, 14, 30, 60])
        for ep, m, st, hits, body in leak_eps:
            vals = [ep, f'{m} -> {st}', ', '.join(hits), body]
            for cc, v in enumerate(vals, 1):
                cell = dd.cell(row=row, column=cc, value=sanitize(v))
                cell.fill = _RED
                if cc in (2, 3, 4):
                    cell.alignment = _WRAP
            row += 1
    else:
        dd.cell(row=row, column=1,
                value='NONE — no stack-trace / SQL / framework / PII / secret signatures '
                      'in any 4xx/5xx error body.').fill = _GRN
        for c in range(1, 5):
            dd.cell(row=row, column=c).fill = _GRN
        row += 1
    row += 1

    # ---- Block D: WAF-Bypass results (if any) ----
    if bypass_results:
        bypass_count = sum(1 for v in bypass_results.values() if v['verdict'] == 'UNSAFE')
        dd.cell(row=row, column=1,
                value=f'D. WAF-Bypass battery: {bypass_count} UNSAFE / '
                      f'{len(bypass_results)} endpoints tested'
                ).font = Font(bold=True)
        row += 1

        row = _write_block_header(dd, row, '',
            ['Endpoint', 'Verdict', 'Variants (summary)', 'Evidence'],
            [52, 10, 50, 70])
        for ep, bv in sorted(bypass_results.items()):
            variant_summary = ' | '.join(
                f"{v['variant']}: {v['cls']}" for v in bv.get('variants', []))
            vals = [ep, bv['verdict'], variant_summary, bv.get('evidence', '')]
            for cc, v in enumerate(vals, 1):
                cell = dd.cell(row=row, column=cc, value=sanitize(v))
                if bv['verdict'] == 'UNSAFE':
                    cell.fill = _RED
                elif bv['verdict'] == 'REVIEW-ERR':
                    cell.fill = _AMB
                else:
                    cell.fill = _GRN
                if cc in (3, 4):
                    cell.alignment = _WRAP
            row += 1

    dd.freeze_panes = 'A4'


# ---- ConfirmedFindings (single sheet with full curl) ----

def _build_confirmed_findings(wb, raw_rows, by_ep, methods, fail_closed):
    if 'ConfirmedFindings' in wb.sheetnames:
        del wb['ConfirmedFindings']
    cf_ws = wb.create_sheet('ConfirmedFindings')

    # Run classify_endpoint on every endpoint to get fail-closed findings.
    # The sheet must stay consistent with the Result sheet's mode: in
    # standard (non-fail-closed) mode the Result sheet marks 4xx/5xx as
    # Safe, so only 'data' findings are listed here. In fail-closed mode,
    # all Unsafe sub-labels are listed.
    findings = []
    for ep, rlist in by_ep.items():
        mm = {r['method']: r for r in rlist}
        verdict, sublabel, evidence, leaks, data_samples = classify_endpoint(ep, mm)
        if verdict == 'Unsafe':
            if not fail_closed and sublabel != 'data':
                continue
            fq, api = api_path(ep)
            # Build curl commands for each finding method
            curl_commands = {}
            resp_bodies = {}
            for method, st, ln, snippet in data_samples:
                rr = mm.get(method, {})
                headers = {
                    'User-Agent': 'Mozilla/5.0 API-AuthScan/2.0',
                }
                if method in ('POST', 'PUT', 'PATCH'):
                    headers['Content-Type'] = 'application/json'
                    curl_commands[method] = _curl_string(method, ep, headers, '{}')
                else:
                    curl_commands[method] = _curl_string(method, ep, headers)
                resp_bodies[method] = snippet

            # If no data samples but leak findings, capture the leak method.
            # Covers both LEAK_PATTERNS hits and 4xx/5xx param-contract
            # disclosure (e.g. "missing field: customerId") which
            # classify_endpoint flags but LEAK_PATTERNS does not.
            if not data_samples and leaks:
                for m in methods:
                    rr = mm.get(m, {})
                    if rr.get('status') and 400 <= rr['status'] < 600:
                        btext = str(rr.get('body', '') or '')
                        lh = [lbl for pat, lbl in LEAK_PATTERNS if re.search(pat, btext, re.I)]
                        if 'param-contract' in leaks:
                            hints = param_contract_hints(btext)
                            if hints:
                                lh.append('param-contract')
                        if lh:
                            headers = {'User-Agent': 'Mozilla/5.0 API-AuthScan/2.0'}
                            if m in ('POST', 'PUT', 'PATCH'):
                                headers['Content-Type'] = 'application/json'
                                curl_commands[m] = _curl_string(m, ep, headers, '{}')
                            else:
                                curl_commands[m] = _curl_string(m, ep, headers)
                            resp_bodies[m] = btext[:500]

            findings.append({
                'rank': 0,  # assigned after sort
                'endpoint': ep,
                'fqdn': fq,
                'api': api,
                'verdict': verdict,
                'sublabel': sublabel,
                'method': ', '.join(m for m, _, _, _ in data_samples) if data_samples else methods[0],
                'status': data_samples[0][1] if data_samples else 'leak',
                'length': data_samples[0][2] if data_samples else 0,
                'curl': curl_commands,
                'response': resp_bodies,
                'leaks': leaks,
                'evidence': evidence,
                'fail_closed': fail_closed,
            })

    # Score and rank
    def score(f):
        s = 0
        if f['sublabel'] == 'data':
            s += 50
            body_text = ' '.join(f['response'].values()).lower()
            # PII
            if re.search(r'password|secret|token|ssn|aadhar|pan|passport|'
                        r'account.?number|ifsc|credit.?card|debit.?card', body_text):
                s += 30
            # Financial
            if re.search(r'balance|amount|payment|invoice|billing|transaction|'
                        r'ledger|refund|order|price|cost', f['api'].lower()):
                s += 25
            # Health
            if re.search(r'patient|medical|diagnosis|prescription|health|lab|'
                        r'report|specimen', f['api'].lower()):
                s += 20
            # Write
            if re.search(r'save|create|update|delete|remove|post|put|patch|'
                        r'execute|process|trigger|import', f['api'].lower()):
                s += 15
            # Export
            if re.search(r'export|download|report|bulk|dump|all|list|search|'
                        r'query|csv|xlsx|pdf', f['api'].lower()):
                s += 10
        elif f['sublabel'] == 'leak':
            s += 40
            if 'sql-leak' in f['leaks'] or 'stack-trace' in f['leaks']:
                s += 15
            if 'possible-pii-email' in f['leaks']:
                s += 20
            if 'possible-secret' in f['leaks']:
                s += 25
            if 'version-banner' in f['leaks'] or 'db-driver' in f['leaks']:
                s += 10
        return s

    findings.sort(key=lambda f: -score(f))
    for i, f in enumerate(findings, 1):
        f['rank'] = i

    if not findings:
        cf_ws.append(['No unsafe endpoints found.'])
        cf_ws['A1'].fill = _GRN
        cf_ws.freeze_panes = 'A2'
        return

    # Write findings
    cf_cols = ['Rank', 'Verdict', 'Sublabel', 'Host', 'Endpoint', 'Method',
               'HTTP', 'Leak types',
               'Curl request (GET)', 'Curl request (POST)',
               'Response body (GET)', 'Response body (POST)',
               'Evidence', 'Note']
    cf_widths = [6, 10, 12, 24, 55, 10, 8, 25, 50, 50, 60, 60, 70, 40]
    _hdr(cf_ws, cf_cols, cf_widths)

    for f in findings:
        curl_get = ''
        curl_post = ''
        resp_get = ''
        resp_post = ''
        for m, curl in f['curl'].items():
            if m == 'GET':
                curl_get = curl
                resp_get = f['response'].get(m, '')
            else:
                curl_post = curl
                resp_post = f['response'].get(m, '')

        note = ''
        if f['sublabel'] == 'leak':
            note = f'Fail-closed: error body discloses {", ".join(f["leaks"])}'
        elif f['sublabel'] == 'data':
            note = 'Unauthenticated data payload returned'
        elif f['sublabel'] == 'suspected':
            note = 'Mixed signals: WAF block on some methods, no clean auth on others'
        elif f['sublabel'] == 'unverified-error':
            note = 'All methods errored or timed out; could not verify safety'

        row_data = [f['rank'], f['verdict'], f['sublabel'],
                    sanitize(f['fqdn']), sanitize(f['api']),
                    f['method'], f['status'],
                    ', '.join(f['leaks']) if f['leaks'] else '',
                    sanitize(curl_get), sanitize(curl_post),
                    sanitize(resp_get)[:5000], sanitize(resp_post)[:5000],
                    sanitize(f['evidence'])[:500],
                    note]
        cf_ws.append(row_data)
        r_idx = cf_ws.max_row
        fill = _RED if f['verdict'] == 'Unsafe' else _AMB
        for c in cf_ws[r_idx]:
            c.fill = fill
        for c_idx in (9, 10, 11, 12, 13, 14):
            cf_ws.cell(row=r_idx, column=c_idx).alignment = _WRAP

    cf_ws.freeze_panes = 'A2'


# ---- Summary ----

def _build_summary(wb, eps, rows_out, na_set, now, inventory_name,
                   fail_closed=False):
    if 'Summary' in wb.sheetnames:
        del wb['Summary']
    s = wb.create_sheet('Summary')
    verdicts_exact = Counter(r['verdict'] for r in rows_out)

    # Overall metrics
    total_ep = len(set(eps))
    total_tested = sum(1 for r in rows_out if not r['verdict'].startswith('N/A'))
    total_na = sum(1 for r in rows_out if r['verdict'].startswith('N/A'))
    total_unsafe = sum(1 for r in rows_out if r['verdict'].startswith('Unsafe'))
    total_safe = sum(1 for r in rows_out if r['verdict'].startswith('Safe'))

    row = 1
    s.cell(row=row, column=1, value='API Scanner — Test & Status Summary').font = Font(bold=True, size=14, color='305496')
    row += 1
    s.cell(row=row, column=1, value=f'Generated {now} | Inventory: {inventory_name}').font = Font(italic=True, size=9)
    row += 2

    # Metrics table
    metrics = [
        ['Metric', 'Value'],
        ['Total unique endpoints', total_ep],
        ['Endpoints tested (reachable)', total_tested],
        ['Endpoints not tested (N/A)', total_na],
        ['Unsafe (unauth exposure)', total_unsafe],
        ['Safe', total_safe],
        ['N/A (unreachable)', total_na],
        ['Fail-closed scanning', 'YES' if fail_closed else 'NO'],
    ]
    hdr_row = row
    for m_row in metrics:
        s.append(m_row)
        row += 1
    for c in s[hdr_row]:
        c.fill = _HEAD
        c.font = Font(color='FFFFFF', bold=True)
    s['A' + str(hdr_row)].font = Font(bold=True, color='FFFFFF')
    s['B' + str(hdr_row)].font = Font(bold=True, color='FFFFFF')
    row += 1  # blank row

    # Unsafe sub-labels
    row_start = row
    s.cell(row=row, column=1, value='Unsafe sub-labels').font = Font(bold=True)
    row += 1
    sub_counts = Counter()
    for v in verdicts_exact:
        if v.startswith('Unsafe'):
            sub = v.split('(', 1)[1].rstrip(')') if '(' in v else 'data'
            sub_counts[sub] += 1
    for sub, cnt in sorted(sub_counts.items(), key=lambda x: -x[1]):
        s.append([f'  Unsafe ({sub})', cnt])
        row += 1
    row += 1  # blank row

    # Full verdict breakdown
    s.cell(row=row, column=1, value='Verdict breakdown (all sub-labels)').font = Font(bold=True)
    row += 1
    for v, cnt in sorted(verdicts_exact.items(), key=lambda x: -x[1]):
        s.append([f'  {v}', cnt])
        row += 1

    s.column_dimensions['A'].width = 34
    s.column_dimensions['B'].width = 16


# ---- Helpers ----

def by_ep_from_rows(raw_rows):
    """Group raw rows by endpoint."""
    by_ep = defaultdict(list)
    for r in raw_rows:
        by_ep[r['endpoint']].append(r)
    return by_ep


def _body_type(r):
    """Get body type from a raw result."""
    return (r.get('content_type') or '').lower()


def _is_trivial_simple(body_bytes, body_type, path):
    """Simplified trivial check for the reporter (avoid circular imports)."""
    try:
        from .utils import is_trivial_body
        return is_trivial_body(body_bytes or b'', body_type, path)
    except Exception:
        return False


def _best_live_result(rlist):
    """Pick the most significant result from a method list."""
    best = None
    best_score = 999
    for r in rlist:
        st = r.get('status')
        if st is None:
            score = 10
        elif r.get('waf'):
            score = 5
        elif st in (401, 403):
            score = 4
        elif st == 404:
            score = 3
        elif 200 <= st < 300 and (r.get('length') or 0) > 0:
            score = 0
        else:
            score = 6
        if score < best_score:
            best_score = score
            best = r
    return best or {}


# ---- CLI ----

def main():
    import argparse
    ap = argparse.ArgumentParser(description='Build api_scanner result workbook')
    ap.add_argument('raw', help='raw scan JSON (*.raw.json)')
    ap.add_argument('-o', '--output', required=True, help='output workbook')
    ap.add_argument('--endpoints', help='endpoints list (.txt or .xlsx) for the API List sheet')
    ap.add_argument('--methods', default=','.join(['GET','POST','PUT','PATCH','DELETE','OPTIONS']),
                    help='method list used in the scan (default: GET,POST,PUT,PATCH,DELETE,OPTIONS)')
    ap.add_argument('--unreachable', help='file of unreachable endpoint URLs (one per line, -> N/A rows)')
    ap.add_argument('--bypass', help='WAF bypass results JSON (adds Deep Dive block D)')
    ap.add_argument('--inventory', default='', help='inventory file name (shown in sheet headers)')
    ap.add_argument('--fail-closed', action='store_true',
                    help='set if the scan used --fail-closed (drives fail-closed findings sheet)')
    a = ap.parse_args()

    raw = json.load(open(a.raw))
    methods = [m.strip().upper() for m in a.methods.split(',') if m.strip()]

    eps = []
    if a.endpoints:
        if a.endpoints.endswith('.xlsx'):
            from .scanner import load_endpoints_xlsx
            eps = load_endpoints_xlsx(a.endpoints)
        else:
            from .scanner import load_endpoints
            eps = load_endpoints(a.endpoints)

    unreachable = None
    if a.unreachable:
        unreachable = [l.strip() for l in open(a.unreachable) if l.strip()]

    bypass = None
    if a.bypass and os.path.exists(a.bypass):
        bypass = json.load(open(a.bypass))

    build_workbook(a.output, eps, raw, methods,
                   unreachable_eps=unreachable,
                   bypass_results=bypass,
                   inventory_name=a.inventory,
                   fail_closed=a.fail_closed)


if __name__ == '__main__':
    main()
