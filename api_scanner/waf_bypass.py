#!/usr/bin/env python3
"""WAF bypass battery with path-traversal and encoding variants.

Runs a variant battery against previously-Safe endpoints that had WAF blocks
or non-trivial 2xx responses, trying alternate request shapes:

  Standard (all endpoints):
    GET / POST / OVR (X-HTTP-Method-Override) with browser UA
    GET / POST with scanner UA (rules out UA-keyed WAF rules)
    OPTIONS (CORS + allowed-methods enumeration)
  Path-traversal / encoding (added when include_traversal=True):
    /admin/d/..          (directory traversal)
    /admin/%2e%2e/..     (URL-encoded dots)
    /admin/..;/          (IIS/ASP.NET semicolon bypass)
    /admin/.;/           (dot semicolon)
    /ADMIN/../           (mixed case)
    double-encoded path
    trailing dot
    semicolon parameter confusion

Per-variant classification:
  DATA   — non-WAF 2xx with non-trivial payload
  TRIV   — empty / flag-only / health
  AUTH   — 401 / 403
  WAF    — WAF block page detected
  NODATA — 4xx / 5xx with no data
  ERR    — timeout / connection error

Endpoint verdict:
  UNSAFE       any variant returned DATA
  SAFE         all variants returned WAF / AUTH / NODATA / TRIV
  REVIEW-ERR   all variants ERR (needs sequential retry with pacing)

Path-traversal variants attempt to bypass WAF URL-pattern matching by:
  - /admin/d/..          (directory traversal)
  - /admin/%2e%2e/..     (URL-encoded dots)
  - /admin/..;/          (IIS/ASP.NET separator)
  - /admin/.;/           (dot semicolon)
  - /admin/%ef%bc%8e/..  (UTF-8 fullwidth dot)
  - /admin\\..\\         (backslash traversal)
"""

import json
import re
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote

import requests
import urllib3

from .utils import (is_waf_block, is_trivial_body, classify_body_type,
                   cred_gate_hits, api_path)

urllib3.disable_warnings()

BROWSER_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
SCANNER_UA = 'Mozilla/5.0 API-AuthScan/2.0'


# ---- Path-traversal variant generator ----

def path_traversal_variants(endpoint):
    """Generate path-traversal and encoding variants of an endpoint URL.

    These attempt to bypass WAF URL-pattern matching by obscuring the path.
    Only generates variants that are structurally different from the original.

    Args:
        endpoint: Original URL string.

    Returns:
        List of (label, url) tuples.
    """
    variants = []
    parsed = urlparse(endpoint)

    # Only mutate the path component
    path = parsed.path

    # Variant 1: /admin/d/.. → resolves back to /admin/
    if re.search(r'/admin(/|$)', path, re.I):
        new_path = re.sub(r'/admin(/|$)', '/admin/d/..\\1', path, count=1, flags=re.I)
        variants.append(('admin-dotdot', parsed._replace(path=new_path).geturl()))

    # Variant 2: /admin/%2e%2e/.. → URL-encoded dots
        new_path = re.sub(r'/admin(/|$)', '/admin/%2e%2e/%2e%2e\\1', path, count=1, flags=re.I)
        variants.append(('admin-encoded', parsed._replace(path=new_path).geturl()))

    # Variant 3: /admin/..;/  → IIS/ASP.NET semicolon bypass
        new_path = re.sub(r'/admin(/|$)', '/admin/..;\\1', path, count=1, flags=re.I)
        variants.append(('admin-dotsemi', parsed._replace(path=new_path).geturl()))

    # Variant 4: /admin/.;/ → dot-semicolon
        new_path = re.sub(r'/admin(/|$)', '/admin/.;\\1', path, count=1, flags=re.I)
        variants.append(('admin-dotsemi2', parsed._replace(path=new_path).geturl()))

    # Variant 5: Mixed case /ADMIN/../ (case bypass)
        new_path = re.sub(r'/admin(/|$)', '/ADMIN/../\\1', path, count=1, flags=re.I)
        variants.append(('admin-mixedcase', parsed._replace(path=new_path).geturl()))

    # Variant 6: Double-encode the path (general bypass, not admin-only)
    from urllib.parse import quote
    path_enc = quote(parsed.path, safe='/')
    double_enc_path = quote(path_enc, safe='/')
    variants.append(('double-encoded', parsed._replace(path=double_enc_path).geturl()))

    # Variant 7: Add trailing slash + dot (general)
    variants.append(('trailing-dot', endpoint.rstrip('/') + '/.'))

    # Variant 8: Semicolon path confusion — a ';' appended to the path
    # (before any query string) can fool WAF pattern matching that keys
    # on exact path strings. Query string preserved.
    base, query = endpoint.split('?', 1) if '?' in endpoint else (endpoint, '')
    variants.append(('param-semicolon', base.rstrip('/') + ';' +
                     ('?' + query if query else '')))

    return variants


# ---- Core bypass test ----

def _classify_variant(status, body_bytes, path, content_type=''):
    """Classify one variant's response (WAF check included)."""
    if status is None:
        return 'ERR'
    if is_waf_block(status, body_bytes, content_type):
        return 'WAF'
    if status in (401, 403):
        return 'AUTH'
    # Credential-gated 2xx: returns 200 with "User Id is required" etc.
    # instead of 401. Not data exposure.
    if 200 <= status < 300:
        btext = body_bytes.decode('utf-8', 'replace') if isinstance(body_bytes, bytes) else str(body_bytes)
        if cred_gate_hits(btext):
            return 'AUTH'
        bt = classify_body_type(content_type, body_bytes)
        if is_trivial_body(body_bytes, bt, path):
            return 'TRIV'
        return 'DATA'
    return 'NODATA'


def test_endpoint(ep, mm, timeout, include_traversal=True):
    """Run bypass battery on one endpoint.

    Args:
        ep:                  Endpoint URL.
        mm:                  Method map {method: raw_result} from scan.
        timeout:             Per-request timeout.
        include_traversal:   If True, add path-traversal variants for admin paths.

    Returns:
        dict with endpoint, verdict, variants, evidence.
    """
    sess = requests.Session()
    sess.verify = False
    path = api_path(ep)[1]

    # Build variant list
    variants = []

    # 1. GET with browser UA
    variants.append(('GET-B', 'GET', {
        'User-Agent': BROWSER_UA}, None))

    # 2. POST {} with browser UA
    variants.append(('POST-B', 'POST', {
        'User-Agent': BROWSER_UA,
        'Content-Type': 'application/json'}, b'{}'))

    # 3. POST {} + X-HTTP-Method-Override: GET
    variants.append(('OVR-B', 'POST', {
        'User-Agent': BROWSER_UA,
        'Content-Type': 'application/json',
        'X-HTTP-Method-Override': 'GET'}, b'{}'))

    # 4. GET with scanner UA (different UA may bypass UA-keyed rules)
    variants.append(('GET-S', 'GET', {'User-Agent': SCANNER_UA}, None))

    # 5. POST {} with scanner UA
    variants.append(('POST-S', 'POST', {
        'User-Agent': SCANNER_UA,
        'Content-Type': 'application/json'}, b'{}'))

    # 6. OPTIONS
    variants.append(('OPTIONS', 'OPTIONS', {
        'User-Agent': BROWSER_UA,
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'Content-Type'}, None))

    # 7-13. Path-traversal variants (for admin/internal paths)
    if include_traversal:
        for label, traversal_url in path_traversal_variants(ep):
            variants.append((
                f'TRAV-{label}',
                'GET',
                {'User-Agent': BROWSER_UA},
                None,
                traversal_url,  # override URL
            ))

    out = []
    for v in variants:
        v_label = v[0]
        method = v[1]
        headers = v[2]
        data = v[3]
        override_url = v[4] if len(v) > 4 else ep

        try:
            r = sess.request(method, override_url, data=data,
                             headers=headers, allow_redirects=False,
                             timeout=timeout)
            body = r.content
            ct = r.headers.get('Content-Type', '')
            waf = is_waf_block(r.status_code, body, ct)
            cls = _classify_variant(r.status_code, body, path, ct)
            ev = f'{v_label}->{r.status_code}'
            if waf:
                ev += ' [WAF BLOCK]'
            if cls == 'DATA':
                ev += " body='" + body[:150].decode('utf-8', 'replace') + "'"
            out.append(dict(variant=v_label, status=r.status_code,
                           length=len(body), cls=cls, evidence=ev,
                           content_type=ct))
            # Short-circuit on DATA
            if cls == 'DATA':
                break
        except requests.exceptions.Timeout:
            out.append(dict(variant=v_label, status=None, length=0,
                           cls='ERR', evidence=f'{v_label}->TIMEOUT'))
        except Exception as e:
            out.append(dict(variant=v_label, status=None, length=0,
                           cls='ERR',
                           evidence=f'{v_label}->ERR {type(e).__name__}: {str(e)[:60]}'))

    # Verdict
    cls_set = [o['cls'] for o in out]
    if 'DATA' in cls_set:
        verdict = 'UNSAFE'
    elif all(c == 'ERR' for c in cls_set):
        verdict = 'REVIEW-ERR'
    else:
        verdict = 'SAFE'

    return dict(endpoint=ep, verdict=verdict, variants=out,
                evidence='; '.join(o['evidence'] for o in out))


def run_bypass_battery(raw_path, out_path, timeout=20, workers=16,
                       include_traversal=True, prefilter=None):
    """Run the WAF bypass battery on endpoints that need it.

    Args:
        raw_path:           Path to the raw scan JSON (*.raw.json from run_scan.py).
        out_path:           Output JSON path for bypass results.
        timeout:            Per-request timeout.
        workers:            Thread pool size.
        include_traversal:  Whether to include path-traversal variants.
        prefilter:          Optional callable(endpoint, method_map) -> bool.
                            If provided, only endpoints where it returns True
                            get the bypass battery.

    Returns:
        dict of endpoint -> bypass result.
    """
    raw = json.load(open(raw_path))
    mm = defaultdict(dict)
    for r in raw:
        mm[r['endpoint']][r['method']] = r

    # Default prefilter: WAF-blocked or non-trivial 2xx
    if prefilter is None:
        def prefilter(ep, method_map):
            for v in method_map.values():
                st = v.get('status')
                if st is None:
                    continue
                if v.get('waf'):
                    return True
                if 200 <= st < 300 and (v.get('length') or 0) > 0:
                    return True
            return False

    todo = [ep for ep, m in mm.items() if prefilter(ep, m)]
    print(f'[+] {len(mm)} endpoints | {len(todo)} need bypass battery '
          f'| traversal variants: {include_traversal}', flush=True)

    results = {}
    done = 0
    t0 = time.time()

    # Use smaller worker count for bypass (avoid triggering WAF rate limits)
    bw = min(workers, 8)
    with ThreadPoolExecutor(max_workers=bw) as ex:
        futs = {ex.submit(test_endpoint, ep, mm[ep], timeout, include_traversal): ep
                for ep in todo}
        for f in as_completed(futs):
            ep = futs[f]
            try:
                results[ep] = f.result()
            except Exception as e:
                results[ep] = dict(endpoint=ep, verdict='REVIEW-ERR',
                                  variants=[], evidence=f'submit error: {e}')
            done += 1
            if done % 100 == 0:
                el = time.time() - t0
                eta = (len(todo) - done) / (done / el) if done else 0
                print(f'  .. {done}/{len(todo)} ({done/el:.1f}/s, ETA {eta/60:.1f} min)',
                      flush=True)
            if done % 500 == 0:
                json.dump(results, open(out_path, 'w'))

    json.dump(results, open(out_path, 'w'))
    vc = Counter(v['verdict'] for v in results.values())
    print(f'[+] verdicts: {dict(vc)} | -> {out_path} '
          f'in {(time.time()-t0)/60:.1f} min', flush=True)
    for ep, v in results.items():
        if v['verdict'] == 'UNSAFE':
            print(f'    UNSAFE {ep}: {v["evidence"][:200]}', flush=True)
    return results


# ---- CLI ----

def main():
    import argparse
    ap = argparse.ArgumentParser(
        description='WAF bypass battery — test alternate request shapes '
                    'against WAF-blocked endpoints')
    ap.add_argument('raw', help='raw scan JSON (*.raw.json from api_scan)')
    ap.add_argument('-o', '--output', default='waf_bypass.json',
                    help='output JSON path (default: waf_bypass.json)')
    ap.add_argument('-t', '--timeout', type=int, default=20,
                    help='per-request timeout in seconds (default: 20)')
    ap.add_argument('-w', '--workers', type=int, default=8,
                    help='concurrent bypass threads, capped at 8 '
                         '(default: 8 - higher risks WAF rate-limits)')
    ap.add_argument('--no-traversal', action='store_true',
                    help='disable path-traversal variants')
    ap.add_argument('--prefilter', default='',
                    help='custom prefilter module (module:function)')
    a = ap.parse_args()

    pf = None
    if a.prefilter:
        mod_name, fn_name = a.prefilter.split(':')
        import importlib
        mod = importlib.import_module(mod_name)
        pf = getattr(mod, fn_name)

    run_bypass_battery(a.raw, a.output, a.timeout, a.workers,
                       include_traversal=not a.no_traversal, prefilter=pf)


if __name__ == '__main__':
    main()
