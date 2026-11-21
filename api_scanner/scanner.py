#!/usr/bin/env python3
"""Core scan engine for api_scanner.

Provides:
  load_endpoints          Read URLs from a text file
  load_endpoints_xlsx     Read URLs from an inventory workbook
  tcp_precheck            Quick TCP reachability gate (dead-host detection)
  probe                   Single (endpoint, method) probe with full capture
  scan                    Thread-pool scan of all endpoint x method combos
  consolidate             Raw per-method results → one output row per endpoint
  write_workbook          Write Result sheet + optional live-scan sheet
  is_noise                Filter 405/204/empty-2xx from significance ranking
  evidence_for            Build the semicolon-delimited evidence string
  ev_text                 Format one method's evidence
"""

import argparse
import concurrent.futures as cf
import json
import os
import re
import socket
import sys
import time
import threading
from collections import Counter, defaultdict

import requests
import urllib3
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
import openpyxl

from .utils import (
    is_waf_block, sanitize, api_path, error_type_label, body_snippet,
)
from .classifiers import classify

urllib3.disable_warnings()

# ---- Constants ----
DEFAULT_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
WRITE_METHODS = ('POST', 'PUT', 'PATCH')
USER_AGENT = 'Mozilla/5.0 API-AuthScan/2.0'

COLS = ['FQDN', 'API', 'Method', 'Status Code', 'length',
        'Safe / unsafe', 'remark', 'evidence']
COL_W = [20, 55, 26, 11, 9, 14, 95, 110]


# ---- Input loading ----

def load_endpoints(path):
    """One full URL per line; '#' comments and blanks ignored; deduped in order."""
    seen, eps = set(), []
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            url = line.split('#', 1)[0].strip()
            if not url:
                continue
            m = re.match(r'^(https?)://[^/\s]+(/[^?\s]*)*', url)
            if not m:
                print(f'[!] line {n}: not a valid full URL, skipped: {line.strip()[:80]}',
                      file=sys.stderr)
                continue
            if url not in seen:
                seen.add(url)
                eps.append(url)
    return eps


def load_endpoints_xlsx(xlsx, url_col=None):
    """Endpoint URLs from an existing inventory workbook.

    Finds the URL column automatically: by url_col name, else a header
    containing 'endpoint', else the first column that actually holds
    http(s) URLs.  Returns the de-duplicated URL list (order preserved)."""
    wb = openpyxl.load_workbook(xlsx, read_only=True)
    ws = wb[wb.sheetnames[0]]
    rows = list(ws.iter_rows(values_only=True))
    wb.close()
    if not rows:
        return []
    hrow = 0
    for i, r in enumerate(rows[:5]):
        if sum(1 for v in r if v not in (None, '')) >= 2:
            hrow = i
            break
    headers = [str(v).strip() if v else '' for v in rows[hrow]]
    if url_col:
        idx = next((i for i, h in enumerate(headers)
                    if url_col.lower() in h.lower()), None)
    else:
        idx = next((i for i, h in enumerate(headers) if 'endpoint' in h.lower()), None)
        if idx is None:
            for i in range(len(headers)):
                if any(str(rows[r][i]).strip().lower().startswith(('http://', 'https://'))
                       for r in range(hrow + 1, min(hrow + 10, len(rows)))
                       if i < len(rows[r]) and rows[r][i] is not None):
                    idx = i
                    break
    if idx is None:
        print(f'[!] URL column not found (headers: {headers}); try --url-col',
              file=sys.stderr)
        sys.exit(2)
    seen, eps = set(), []
    for r in rows[hrow + 1:]:
        v = r[idx] if idx < len(r) else None
        url = str(v).strip() if v is not None else ''
        if not url:
            continue
        m = re.match(r'^\s*(https?://[^/\s]+)', url)
        if not m:
            print(f'[!] skipping non-URL value in "{headers[idx]}": {url[:80]}',
                  file=sys.stderr)
            continue
        if url not in seen:
            seen.add(url)
            eps.append(url)
    print(f'[+] sheet "{ws.title}", column "{headers[idx]}": '
          f'{len(eps)} unique endpoints ({len(rows) - hrow - 1} data rows)',
          flush=True)
    return eps


# ---- TCP precheck ----

def tcp_precheck(eps, timeout=5):
    """Quick TCP connect check on each endpoint's host:443.

    Returns:
        (reachable_eps, unreachable_eps)

    Checks per HOST (not per URL): all URLs on a reachable host are
    reachable; all URLs on a dead host are unreachable.
    """
    from urllib.parse import urlparse
    # (host, port) pairs — port comes from the URL (443/80 by default), so
    # http:// endpoints are not wrongly tested against 443.
    host_ports = []
    seen = set()
    for ep in eps:
        p = urlparse(ep)
        port = p.port or (443 if p.scheme == 'https' else 80)
        key = (p.hostname, port)
        if p.hostname and key not in seen:
            seen.add(key)
            host_ports.append(key)

    unreachable = set()
    total = len(host_ports)
    print(f'[+] TCP precheck: {total} unique hosts ...', flush=True)

    for i, (host, port) in enumerate(host_ports, 1):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except (socket.timeout, socket.error, OSError):
            unreachable.add((host, port))
        if i % 50 == 0:
            print(f'  .. {i}/{total}', flush=True)

    def _key(ep):
        p = urlparse(ep)
        return (p.hostname, p.port or (443 if p.scheme == 'https' else 80))

    reachable = [ep for ep in eps if _key(ep) not in unreachable]
    unreachable_eps = [ep for ep in eps if _key(ep) in unreachable]
    dead_list = sorted(unreachable)
    print(f'[+] precheck: {len(reachable)} reachable, {len(unreachable_eps)} unreachable '
          f'({len(dead_list)} dead host:port pairs: '
          f'{", ".join(f"{h}:{p}" for h, p in dead_list[:10])})',
          flush=True)
    return reachable, unreachable_eps


# ---- Probe ----

def probe(sess, ep, method, timeout, err_types=None, err_lock=None):
    """One (endpoint, method) probe. Never raises; errors are captured.

    Args:
        sess:      requests.Session (or equivalent) for the request.
        ep:        Full URL.
        method:    HTTP method.
        timeout:   Per-request timeout in seconds.
        err_types: Optional shared dict for tallying error types across
                   probes. When passed from multiple threads, also pass
                   err_lock (a threading.Lock) protecting it.
        err_lock:  Lock guarding err_types.

    Returns dict with keys:
        endpoint, method, status, length, location, waf, code, message,
        body, content_type, acao, acac, err_type
    """
    body = b''
    status = None
    headers = {}
    err_type = ''

    if err_types is None:
        err_types = {}

    try:
        if method in WRITE_METHODS:
            r = sess.request(method, ep, data=b'{}',
                             headers={'Content-Type': 'application/json'},
                             allow_redirects=False, timeout=timeout)
        else:
            r = sess.request(method, ep, allow_redirects=False, timeout=timeout)
        body = r.content
        status = r.status_code
        headers = {k.lower(): v for k, v in r.headers.items()}
    except requests.exceptions.Timeout:
        err_type = 'TIMEOUT'
    except requests.exceptions.SSLError:
        err_type = 'TLS'
    except requests.exceptions.ConnectionError as e:
        msg = str(e).lower()
        if 'refused' in msg:
            err_type = 'CONNREFUSED'
        elif 'reset' in msg:
            err_type = 'RESET'
        elif 'name or service not known' in msg or 'getaddrinfo' in msg:
            err_type = 'DNS'
        else:
            err_type = 'CONN'
    except Exception as e:
        err_type = error_type_label(e)

    if err_type:
        if err_lock is not None:
            with err_lock:
                err_types[err_type] = err_types.get(err_type, 0) + 1
        else:
            err_types[err_type] = err_types.get(err_type, 0) + 1

    code, msg = _parse_error(body)

    ct = headers.get('content-type', '')
    acao = headers.get('access-control-allow-origin', '')
    acac = headers.get('access-control-allow-credentials', '')

    # Two-tier WAF detection: strong markers on any 2xx; weak markers only on
    # HTML block pages. Prevents JSON data containing words like 'proxy',
    # 'firewall', 'azure' from being misclassified as WAF-blocked (false Safe).
    waf = is_waf_block(status, body, ct)

    return dict(endpoint=ep, method=method, status=status,
                length=len(body) if body else 0,
                location=headers.get('location', ''),
                waf=waf, code=code, message=msg,
                body=body_snippet(body),
                content_type=ct,
                acao=acao, acac=acac,
                err_type=err_type)


def _parse_error(body):
    """Pull (code, message) from a JSON error body when present."""
    code = msg = None
    try:
        j = json.loads(body)
        if isinstance(j, dict):
            for k in ('code', 'errorCode', 'error_code', 'status', 'Code'):
                if j.get(k) not in (None, ''):
                    code = j[k]
                    break
            for k in ('message', 'error', 'detail', 'Message', 'title', 'description',
                      'error_description', 'ErrorDescription'):
                if j.get(k) not in (None, ''):
                    msg = str(j[k])
                    break
    except Exception:
        pass
    return code, msg


# ---- Scan ----

def scan(eps, methods, workers, timeout, on_result=None):
    """Thread-pool scan. Returns list of probe result dicts.

    Args:
        on_result: optional callback(row) invoked as each probe completes
                   (used for live workbook updates). Must be thread-safe.
    """
    sess = requests.Session()
    sess.verify = False
    sess.headers.update({'User-Agent': USER_AGENT})
    rows, total = [], len(eps) * len(methods)
    err_types = {}
    err_lock = threading.Lock()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(probe, sess, ep, m, timeout, err_types, err_lock)
                for ep in eps for m in methods]
        for i, f in enumerate(cf.as_completed(futs)):
            row = f.result()
            rows.append(row)
            if on_result is not None:
                try:
                    on_result(row)
                except Exception:
                    pass  # a live-update hiccup must never kill the scan
            if (i + 1) % 200 == 0:
                print(f'  .. {i + 1}/{total}', flush=True)
    if err_types:
        print(f'[+] error types: {dict(sorted(err_types.items(), key=lambda x: -x[1]))}',
              flush=True)
    return rows


def retry_errors(rows, timeout):
    """Sequential retry for rows that came back as ERR/timeout.

    Once a host fails its retry, remaining rows for the same host are
    skipped (marked unverified) instead of re-hitting a known-dead endpoint
    — a dead-TCP host otherwise turns the retry pass into a multi-hour
    stall (each probe burns the full timeout).
    """
    bad = [r for r in rows if r['status'] is None]
    if not bad:
        return 0
    print(f'[+] retrying {len(bad)} error/timeout rows ...', flush=True)
    sess = requests.Session()
    sess.verify = False
    sess.headers.update({'User-Agent': USER_AGENT})
    still, dead_hosts = 0, set()
    for i, r in enumerate(bad, 1):
        host = r['endpoint'].split('/')[2]
        if host in dead_hosts:
            still += 1
            continue
        r2 = probe(sess, r['endpoint'], r['method'], timeout)
        if r2['status'] is not None:
            r.update(r2)
            print(f'    retry {i}: {r["method"]} {r["endpoint"]} -> {r2["status"]}',
                  flush=True)
        else:
            dead_hosts.add(host)
            still += 1
            print(f'    retry {i}: {r["method"]} {r["endpoint"]} still failing '
                  f'({len(bad) - i + 1} rows on this host skipped)',
                  flush=True)
        time.sleep(1)
    return still


# ---- Consolidation ----

def is_noise(r):
    """405 / 204 / empty-2xx responses never get their own row."""
    if r['status'] is None:
        return False
    if r['status'] in (405, 204):
        return True
    if 200 <= r['status'] < 300 and (r['length'] or 0) == 0:
        return True
    return False


def ev_text(r):
    """Exact per-method evidence: status, WAF flag, code, message, body snippet."""
    if r['status'] is None:
        et = r.get('err_type', '')
        return f"{r['method']}->ERR({et}) {r.get('body','')[:200]}"
    parts = [f"{r['method']}->{r['status']}"]
    if r.get('waf'):
        parts.append('[WAF BLOCK PAGE]')
    if r.get('code') not in (None, ''):
        parts.append(f"code={r['code']}")
    if r.get('message'):
        parts.append(f"msg='{str(r['message'])[:120]}'")
    if r.get('acao'):
        parts.append(f"ACAO={r['acao'][:40]}")
    if r.get('acac'):
        parts.append('ACAC=true')
    s = ' '.join(parts)
    if 200 <= r['status'] < 300 and (r['length'] or 0):
        s += f" body='{(r.get('body') or '')[:200]}'"
    return s


def evidence_for(rlist, methods):
    ordered = sorted(rlist, key=lambda r: methods.index(r['method'])
                     if r['method'] in methods else 99)
    return '; '.join(ev_text(r) for r in ordered)


def consolidate(rlist, methods, fail_closed=False):
    """Raw per-method results for ONE endpoint → a SINGLE output row.

    Method = 'ALL'; Status/length = the most significant response.

    Args:
        fail_closed: if True, 4xx/5xx/400 bodies are leak-scanned in
            classify() so the Result sheet itself carries sub-labeled
            Unsafe verdicts (default False = standard api_scan behavior,
            backward-compatible).
    """
    ep = rlist[0]['endpoint']
    fq, api = api_path(ep)
    rlist = sorted(rlist, key=lambda r: methods.index(r['method'])
                   if r['method'] in methods else 99)

    per = []
    for r in rlist:
        verdict, remark = classify(
            api, r['status'], r['length'],
            r.get('waf', False),
            method=r['method'],
            body=r.get('body', ''),
            content_type=r.get('content_type', ''),
            fail_closed=fail_closed,
        )
        per.append((r, verdict, remark))

    ep_verdict = 'Unsafe' if any(
        v.startswith('Unsafe') for _, v, _ in per) else 'Safe'
    sublabel = ''
    for _, v, rm in per:
        if v.startswith('Unsafe') and '(' in v:
            sublabel = v.split('(', 1)[1].rstrip(')')
            break
    # Display verdict carries the sub-label in fail-closed mode
    # (e.g. "Unsafe (leak)") so the Result sheet stays consistent with
    # ConfirmedFindings/Summary; standard mode keeps the bare "Unsafe".
    verdict_display = (f'Unsafe ({sublabel})'
                       if ep_verdict == 'Unsafe' and sublabel else ep_verdict)

    msum = '; '.join(
        f"{r['method']}->{r['status'] if r['status'] is not None else 'ERR'}"
        + (' [WAF BLOCK PAGE]' if r.get('waf') else '')
        for r, v, rm in per)

    def rank(p):
        r, verdict, _ = p
        st = r['status']
        if verdict.startswith('Unsafe'):
            return 0
        if r.get('waf'):
            return 1
        if st in (401, 403):
            return 2
        if st == 404:
            return 3
        if st == 405:
            return 4
        if st is None:
            return 6
        if 400 <= st < 500:
            return 5
        if st >= 500:
            return 6
        return 7

    sig = [p for p in per if not is_noise(p[0])]
    if not sig:
        rep_status = 405 if any(r['status'] == 405 for r in rlist) else 204
        rep_len, remark = 0, f'no significant response on any method | all: {msum}'
    else:
        r, _, base_remark = min(sig, key=rank)
        rep_status, rep_len = r['status'], r['length']
        remark = f'{base_remark} | all: {msum}'

    return [dict(fqdn=fq, api=api, method='ALL',
                 status=(rep_status if rep_status is not None else 'ERR'),
                 length=rep_len, verdict=verdict_display, sublabel=sublabel,
                 remark=remark,
                 evidence=evidence_for(rlist, methods), url=ep)]


# ---- Workbook writing ----

def write_workbook(xlsx, eps, rows_out, methods, sheet_name='Result',
                   na_rows=None):
    """Write the output workbook.

    Args:
        xlsx:          Output path.
        eps:           Input endpoint list (for API List sheet).
        rows_out:      Consolidated rows (list of dicts).
        methods:       Method list used.
        sheet_name:    Result sheet name.
        na_rows:       Optional list of N/A row dicts to include.
    """
    wb = openpyxl.Workbook()
    src = wb.active
    src.title = 'API List'
    src.append(['Endpoint URL'])
    for ep in eps:
        src.append([ep])
    src.column_dimensions['A'].width = 80

    out = wb.create_sheet(sheet_name)
    out.append(COLS)

    def mkey(r):
        head = r['method'].split(',')[0].strip()
        return methods.index(head) if head in methods else 99

    order = {'Unsafe': 0, 'Safe': 1, 'N/A': 2}
    all_rows = list(rows_out)
    if na_rows:
        all_rows.extend(na_rows)
    all_rows.sort(key=lambda r: (
        order.get(r['verdict'].split('(')[0].strip(), 3)
        if not r['verdict'].startswith('N/A') else 2,
        r['api'], mkey(r)))

    for r in all_rows:
        out.append([sanitize(r['fqdn']), sanitize(r['api']), r['method'],
                    r['status'], r['length'], r.get('verdict', 'Safe'),
                    sanitize(r['remark']), sanitize(r['evidence'])])

    for i, w in enumerate(COL_W, 1):
        out.column_dimensions[get_column_letter(i)].width = w
    for c in out[1]:
        c.fill = PatternFill('solid', fgColor='305496')
        c.font = Font(color='FFFFFF', bold=True)
    wrap = Alignment(wrap_text=True, vertical='top')
    red = PatternFill('solid', fgColor='FFC7CE')
    green = PatternFill('solid', fgColor='C6EFCE')
    grey = PatternFill('solid', fgColor='D9D9D9')
    for row in out.iter_rows(min_row=2):
        v = str(row[5].value or '')
        fill = red if v.startswith('Unsafe') else (grey if v.startswith('N/A') else green)
        for c in row:
            c.fill = fill
            if c.column in (7, 8):
                c.alignment = wrap
    out.freeze_panes = 'A2'
    wb.save(xlsx)


class LiveWorkbookWriter:
    """Append rows to an Excel workbook in real-time during a scan.

    Usage:
        writer = LiveWorkbookWriter(xlsx_path, eps, methods)
        # ... as probes complete ...
        writer.append_raw_row(timestamp, fqdn, api, method, status, length,
                              verdict, content_type, body_snippet)
        writer.flush()  # optional explicit flush
        writer.finalize(rows_out, na_rows)  # call at end
    """

    def __init__(self, xlsx_path, eps, methods,
                 sheet_name='Live Scan', result_sheet='Result',
                 flush_every=50, flush_interval=30):
        self.path = xlsx_path
        self.eps = eps
        self.methods = methods
        self.sheet_name = sheet_name
        self.result_sheet = result_sheet
        self.flush_every = flush_every
        self.flush_interval = flush_interval
        self._buffer = []
        self._lock = threading.Lock()
        self._last_flush = time.time()
        self._counter = 0

        # Create workbook upfront
        wb = openpyxl.Workbook()
        api_sheet = wb.active
        api_sheet.title = 'API List'
        api_sheet.append(['Endpoint URL'])
        for ep in eps:
            api_sheet.append([ep])
        api_sheet.column_dimensions['A'].width = 80

        ls = wb.create_sheet(sheet_name)
        live_cols = ['Timestamp', 'FQDN', 'API', 'Method', 'Status',
                     'Length', 'Verdict', 'Content-Type', 'Body snippet']
        ls.append(live_cols)
        for i, w in enumerate([12, 20, 55, 10, 8, 8, 14, 20, 60], 1):
            ls.column_dimensions[get_column_letter(i)].width = w
        for c in ls[1]:
            c.fill = PatternFill('solid', fgColor='305496')
            c.font = Font(color='FFFFFF', bold=True)
        ls.freeze_panes = 'A2'
        wb.save(self.path)
        self._wb = wb

    def append_raw_row(self, timestamp, fqdn, api, method, status, length,
                       verdict, content_type='', body_snip=''):
        """Thread-safe: buffer a raw probe result row."""
        with self._lock:
            self._buffer.append([
                timestamp, sanitize(fqdn), sanitize(api), method,
                status if status is not None else 'ERR',
                length, verdict, content_type, body_snip[:200]
            ])
            self._counter += 1
            if (self._counter % self.flush_every == 0 or
                    time.time() - self._last_flush > self.flush_interval):
                self._do_flush()

    def flush(self):
        """Explicit flush of the buffer to disk."""
        with self._lock:
            self._do_flush()

    def _do_flush(self):
        if not self._buffer:
            return
        try:
            wb = openpyxl.load_workbook(self.path)
            ls = wb[self.sheet_name]
            wrap = Alignment(wrap_text=True, vertical='top')
            green = PatternFill('solid', fgColor='C6EFCE')
            amber = PatternFill('solid', fgColor='FFEB9C')
            for row_data in self._buffer:
                ls.append(row_data)
                r_idx = ls.max_row
                v = str(row_data[6] or '')
                fill = amber if v == 'Unsafe' else green
                for c in ls[r_idx]:
                    c.fill = fill
                    if c.column in (7, 8, 9):
                        c.alignment = wrap
            wb.save(self.path)
            self._buffer.clear()
            self._last_flush = time.time()
        except Exception as e:
            print(f'[!] live flush error: {e}', flush=True)

    def finalize(self, rows_out, na_rows=None):
        """Write the final result sheet + close."""
        # Final flush of any remaining buffer
        self.flush()
        # Now write the consolidated result sheet
        wb = openpyxl.load_workbook(self.path)
        if self.result_sheet in wb.sheetnames:
            del wb[self.result_sheet]
        out = wb.create_sheet(self.result_sheet)
        out.append(COLS)

        def mkey(r):
            head = r['method'].split(',')[0].strip()
            return self.methods.index(head) if head in self.methods else 99

        order = {'Unsafe': 0, 'Safe': 1, 'N/A': 2}
        all_rows = list(rows_out)
        if na_rows:
            all_rows.extend(na_rows)
        all_rows.sort(key=lambda r: (
            order.get(r['verdict'].split('(')[0].strip(), 3)
            if not r['verdict'].startswith('N/A') else 2,
            r['api'], mkey(r)))

        for r in all_rows:
            out.append([sanitize(r['fqdn']), sanitize(r['api']), r['method'],
                        r['status'], r['length'], r.get('verdict', 'Safe'),
                        sanitize(r['remark']), sanitize(r['evidence'])])

        for i, w in enumerate(COL_W, 1):
            out.column_dimensions[get_column_letter(i)].width = w
        for c in out[1]:
            c.fill = PatternFill('solid', fgColor='305496')
            c.font = Font(color='FFFFFF', bold=True)
        wrap = Alignment(wrap_text=True, vertical='top')
        red = PatternFill('solid', fgColor='FFC7CE')
        green = PatternFill('solid', fgColor='C6EFCE')
        grey = PatternFill('solid', fgColor='D9D9D9')
        for row in out.iter_rows(min_row=2):
            v = str(row[5].value or '')
            fill = red if v.startswith('Unsafe') else (grey if v.startswith('N/A') else green)
            for c in row:
                c.fill = fill
                if c.column in (7, 8):
                    c.alignment = wrap
        out.freeze_panes = 'A2'

        wb.save(self.path)
        print(f'[+] final workbook -> {self.path}', flush=True)


# ---- Main entry ----

def main():
    ap = argparse.ArgumentParser(description='API Scanner — unauthenticated API exposure scanner')
    ap.add_argument('endpoints',
                    help='input: .txt (one full URL per line) or .xlsx '
                         '(inventory workbook - URL column auto-detected)')
    ap.add_argument('-o', '--output', default='api_scan_results.xlsx',
                    help='output workbook (default: api_scan_results.xlsx)')
    ap.add_argument('--url-col', default='',
                    help='for .xlsx input: substring of URL column header')
    ap.add_argument('--sheet', default='Result',
                    help='result sheet name (default: Result)')
    ap.add_argument('--methods', default=','.join(DEFAULT_METHODS),
                    help=f'comma-separated method list (default: {",".join(DEFAULT_METHODS)})')
    ap.add_argument('-w', '--workers', type=int, default=16,
                    help='concurrent probe threads (default: 16)')
    ap.add_argument('-t', '--timeout', type=int, default=25,
                    help='per-request timeout in seconds (default: 25)')
    ap.add_argument('--rescan', action='store_true',
                    help='ignore raw cache and re-hit every endpoint')
    ap.add_argument('--from-cache', action='store_true',
                    help='skip network; re-render from raw cache')
    ap.add_argument('--precheck', action='store_true',
                    help='run TCP precheck and write unreachable hosts to a .txt file')
    ap.add_argument('--fail-closed', action='store_true',
                    help='scan 4xx/5xx/400 bodies for leaks (fail-closed policy)')
    ap.add_argument('--no-live-sheet', action='store_true',
                    help='disable live-updating workbook during scan')
    ap.add_argument('--flush-every', type=int, default=50,
                    help='flush workbook every N probe completions (default: 50)')
    ap.add_argument('--flush-interval', type=int, default=30,
                    help='flush workbook every T seconds (default: 30)')
    a = ap.parse_args()

    methods = [m.strip().upper() for m in a.methods.split(',') if m.strip()]
    if a.endpoints.lower().endswith(('.xlsx', '.xlsm')):
        eps = load_endpoints_xlsx(a.endpoints, a.url_col or None)
    else:
        eps = load_endpoints(a.endpoints)
    if not eps:
        print('error: no valid endpoint URLs found in input', file=sys.stderr)
        sys.exit(2)

    # TCP precheck (keeps the FULL inventory list for API List / N/A rows)
    all_eps = list(eps)
    na_eps = []
    if a.precheck:
        reachable, unreachable = tcp_precheck(eps)
        stem_tmp = a.output.rsplit('.', 1)[0]
        unreach_path = f'{stem_tmp}_unreachable.txt'
        with open(unreach_path, 'w') as f:
            for ep in unreachable:
                f.write(ep + '\n')
        print(f'[+] unreachable hosts written to {unreach_path}', flush=True)
        eps = reachable
        na_eps = unreachable

    stem = a.output.rsplit('.', 1)[0]
    cache, findings = f'{stem}.raw.json', f'{stem}.findings.json'

    # Build N/A (grey) consolidated rows for precheck-unreachable endpoints so
    # the Result sheet still contains every inventory URL (0 missing / 0 extra).
    na_rows = []
    for ep in na_eps:
        fq, api = api_path(ep)
        msum = '; '.join(f'{m}->ERR' for m in methods)
        na_rows.append(dict(fqdn=fq, api=api, method='ALL', status='ERR',
                            length=0, verdict='N/A (unreachable)', sublabel='',
                            remark=('NOT TESTED - host unreachable (TCP precheck) '
                                    f'| all: {msum}'),
                            evidence='; '.join(f'{m}->ERR precheck' for m in methods),
                            url=ep))

    # Scan or use cache
    live_writer = None
    if not a.no_live_sheet and not a.from_cache:
        live_path = a.output if a.output.endswith('.xlsx') else a.output + '.xlsx'
        # API List must contain the FULL inventory (scanned + N/A)
        live_writer = LiveWorkbookWriter(
            live_path, all_eps, methods,
            result_sheet=a.sheet,
            flush_every=a.flush_every,
            flush_interval=a.flush_interval)

    from datetime import datetime

    # Live callback for both fresh scans and rescans (both hit the network,
    # so real-time progress applies to both).
    if live_writer:
        # Callback that fires as each probe completes -> rows appear in the
        # workbook DURING the scan (the live-validate requirement).
        def _live_cb(row):
            ts = datetime.now().strftime('%H:%M:%S')
            fq, api = api_path(row['endpoint'])
            live_writer.append_raw_row(
                ts, fq, api, row['method'],
                row['status'], row['length'],
                'ERR' if row['status'] is None else 'pending',
                row.get('content_type', ''),
                row.get('body', ''))
    else:
        _live_cb = None

    if a.from_cache:
        if not os.path.exists(cache):
            print(f'error: {cache} not found for --from-cache', file=sys.stderr)
            sys.exit(2)
        rows = json.load(open(cache))
        print(f'[+] reusing cached {len(rows)} responses from {cache}')
    elif a.rescan or not os.path.exists(cache):
        print(f'[+] scanning {len(eps)} endpoints x {len(methods)} methods '
              f'({a.workers} workers, {a.timeout}s timeout) ...', flush=True)
        rows = scan(eps, methods, a.workers, a.timeout, on_result=_live_cb)
        still = retry_errors(rows, a.timeout)
        if still:
            print(f'[!] {still} rows still erroring - flagged ERR in the sheet')
        json.dump(rows, open(cache, 'w'))
        print(f'[+] scanned {len(rows)} responses -> {cache}')
    else:
        rows = json.load(open(cache))
        print(f'[+] {cache} exists - reusing cached {len(rows)} responses '
              f'(use --rescan to force a fresh scan)')
        # Cache path: fill the live sheet from cached rows (re-render)
        if live_writer:
            for r in rows:
                ts = datetime.now().strftime('%H:%M:%S')
                fq, api = api_path(r['endpoint'])
                live_writer.append_raw_row(
                    ts, fq, api, r['method'], r['status'], r['length'],
                    'ERR' if r['status'] is None else 'pending',
                    r.get('content_type', ''), r.get('body', ''))

    # Consolidate (reachable rows only; N/A rows appended separately)
    by_ep = defaultdict(list)
    for r in rows:
        by_ep[r['endpoint']].append(r)
    rows_out = []
    for ep in eps:
        if ep in by_ep:
            rows_out.extend(consolidate(by_ep[ep], methods,
                                        fail_closed=a.fail_closed))

    # Finalize
    if live_writer:
        live_writer.finalize(rows_out, na_rows=na_rows)
    else:
        write_workbook(a.output, all_eps, rows_out + na_rows, methods, a.sheet,
                       na_rows=None)

    unf = [r for r in rows_out if r['verdict'].startswith('Unsafe')]
    json.dump(unf, open(findings, 'w'), indent=2)

    print(f'[+] verdicts: {dict(Counter(r["verdict"] for r in rows_out))}')
    print(f'[+] N/A (unreachable): {len(na_rows)}')
    print(f'[+] WAF-block responses: '
          f'{sum(1 for r in rows if r.get("waf"))} '
          f'({len({r["endpoint"] for r in rows if r.get("waf")})} endpoints)')
    print(f'[+] errors/timeouts: {sum(1 for r in rows if r["status"] is None)}')
    print(f'[+] Unsafe findings: {len(unf)}')
    for f in unf:
        print(f'    {f["method"]:22} {f["status"]} {f["api"]}')

    print(f'[+] {len(rows_out)} rows for {len(by_ep)} endpoints -> {a.output} '
          f'(sheet "{a.sheet}")')
    print(f'[+] findings -> {findings}')


if __name__ == '__main__':
    main()
