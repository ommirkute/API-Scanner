#!/usr/bin/env python3
"""Classification logic for api_scanner.

Two classifiers:
  classify()         — single (endpoint, status, ...) → (verdict, remark)
                       Used during consolidation; standard (non-fail-closed) mode.
  classify_endpoint() — full endpoint method map → (verdict, sublabel, evidence, leaks, data)
                       Used by report builder and the new --fail-closed pipeline.
"""

import re

from .utils import (
    LEAK_PATTERNS, CRED_GATE_PATTERNS,
    HEALTH_RE, is_trivial_body, leak_hits, cred_gate_hits,
    param_contract_hints,
    body_snippet, api_path, classify_body_type,
)


# ---- Single-result classifier (backward-compatible) ----

def classify(api, status, length, waf, method='', body=b'',
             content_type='', fail_closed=False):
    """(verdict, remark) for one (endpoint, status, length, waf, method, body).

    Default behavior is standard mode; the fail_closed kwarg opts into
    leak-scanning of error bodies.

    Note on CORS: ACAO/ACAC headers are captured for context only (they
    appear in the evidence string) and never drive a verdict. If an
    endpoint returns genuine unauthenticated data, that data is the
    finding regardless of CORS headers; a CORS-only endpoint with an
    empty/trivial body classifies on its body.

    Args:
        api:            Full endpoint URL.
        status:         HTTP status code or None for errors.
        length:         Response body length in bytes.
        waf:            True if body matched a WAF block-page signature.
        method:         HTTP method name.
        body:           Response body (bytes or str).
        content_type:   Response Content-Type header.
        fail_closed:    If True, scan 4xx/5xx/400 bodies for leaks.
    """
    if status is None:
        return ('Safe',
                'request error/timeout - no data returned; retry manually')

    if waf:
        return ('Safe',
                f'blocked at WAF - HTTP {status} is a block page '
                f'(support ID), no data returned')

    if status in (401, 403):
        return ('Safe', f'auth enforced ({status}) - no data without credentials')

    if status == 405:
        return 'Safe', 'method not allowed (405) - rejected at gateway'

    if 300 <= status < 400:
        return ('Safe',
                f'{status} redirect (SSO/login) - no data returned unauthenticated')

    if 200 <= status < 300:
        # 204 or empty body
        if status == 204 or (length or 0) == 0:
            return ('Safe',
                    f'{status} empty response - no data returned unauthenticated')

        # Normalize body to bytes
        if isinstance(body, str):
            body_bytes = body.encode('utf-8')
        else:
            body_bytes = body or b''

        # OPTIONS Allow advertisement
        if method == 'OPTIONS':
            s = body_bytes.decode('utf-8', 'replace')
            toks = [t for t in re.split(r'[,\s]+', s.strip()) if t]
            _ALLOW = {'GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','TRACE','CONNECT'}
            if toks and all(t.upper() in _ALLOW for t in toks):
                return ('Safe',
                        f"OPTIONS 'Allow' advertisement - lists supported methods only "
                        f'("{s.strip()}"), no data returned')

        # Health endpoints
        if HEALTH_RE.search(api):
            return ('Safe',
                    'health/status check endpoint - open by design; '
                    'returns service name/version only, no business data')

        # CAPTCHA
        if 'captcha' in api.lower():
            return ('Safe',
                    'CAPTCHA challenge returned unauthenticated - pre-login '
                    'endpoint, by design, non-sensitive')

        # Credential-gated 2xx (returns 200 with "User Id is required" etc.)
        btext = body_bytes.decode('utf-8', 'replace')
        cg = cred_gate_hits(btext)
        if cg:
            return ('Safe (auth-gated)',
                    f'credential-gated 2xx ({", ".join(cg)}) - returns auth '
                    f'error message with HTTP 200 instead of 401; no data '
                    f'returned without valid credentials')

        # Trivial body check
        bt = classify_body_type(content_type, body_bytes)
        if is_trivial_body(body_bytes, bt, api):
            return ('Safe (trivial)',
                    f'{status} returned a flag-only success stub '
                    f'("{body_snippet(body_bytes, 60)}") - no data payload; '
                    f'deep-dive recommended before reporting exposure')

        # Non-trivial 2xx with data
        if fail_closed:
            return ('Unsafe (data)',
                    f'unauthenticated {status} - {length} bytes returned '
                    f'without credentials')
        return ('Unsafe',
                f'unauthenticated {status} - {length} bytes returned without credentials')

    if status == 400:
        btext = body.decode('utf-8', 'replace') if isinstance(body, bytes) else str(body or '')
        if fail_closed:
            lh = leak_hits(btext)
            if lh:
                return ('Unsafe (leak)',
                        f'400 validation error discloses internal details: '
                        f'{", ".join(lh)} | body: {body_snippet(body, 200)}')
            # Check for API contract disclosure
            cg = cred_gate_hits(btext)
            if cg:
                return ('Unsafe (leak)',
                        f'400 reveals credential/parameter requirements: '
                        f'{", ".join(cg)} | body: {body_snippet(body, 200)}')
            # Check for parameter/field name disclosure ("additional
            # parameter is required", "customerId is required", ...)
            param_hints = param_contract_hints(btext)
            if param_hints:
                return ('Unsafe (leak)',
                        f'400 discloses API parameter contract: '
                        f'{", ".join(param_hints[:5])} | '
                        f'body: {body_snippet(body, 200)}')
        return ('Safe', '400 payload validation - endpoint reachable, no data / no auth bypass')

    if status == 404:
        if fail_closed:
            lh = leak_hits(body.decode('utf-8', 'replace') if isinstance(body, bytes) else str(body or ''))
            if lh:
                return ('Unsafe (leak)',
                        f'404 error body discloses internals: '
                        f'{", ".join(lh)} | body: {body_snippet(body, 200)}')
        return ('Safe', '404 - endpoint not found on gateway (removed/renamed); no exposure')

    if status in (408, 410, 414, 415, 429):
        return ('Safe', f'{status} - no data returned')

    if 400 <= status < 500:
        if fail_closed:
            btext = body.decode('utf-8', 'replace') if isinstance(body, bytes) else str(body or '')
            lh = leak_hits(btext)
            if lh:
                return ('Unsafe (leak)',
                        f'{status} error body discloses internals: '
                        f'{", ".join(lh)} | body: {body_snippet(body, 200)}')
        return ('Safe', f'{status} client error unauthenticated; no data returned')

    # 5xx
    if status >= 500:
        if fail_closed:
            btext = body.decode('utf-8', 'replace') if isinstance(body, bytes) else str(body or '')
            lh = leak_hits(btext)
            if lh:
                return ('Unsafe (leak)',
                        f'{status} error body discloses internals: '
                        f'{", ".join(lh)} | body: {body_snippet(body, 200)}')
        return ('Safe', f'{status} backend error unauthenticated; no data returned')

    return ('Safe', f'{status} - no data returned')


# ---- Full-endpoint classifier (fail-closed) ----

def classify_endpoint(ep, method_map):
    """Classify an endpoint given all its per-method results.

    Args:
        ep:         Full endpoint URL.
        method_map: {method_str: result_dict} from scan results.

    Returns:
        (verdict, sublabel, evidence_str, leaks_list, data_samples)
        - verdict:       SAFE | Unsafe
        - sublabel:      '' | 'data' | 'leak' | 'suspected' | 'unverified-error'
        - evidence_str:  compact per-method summary
        - leaks_list:    list of leak-labels found in error bodies
        - data_samples:  list of (method, status, snippet) for data 2xx
    """
    path = api_path(ep)[1]
    leaks_all = []
    data_2xx = []
    waf_2xx = []
    unverified = []
    confirmed_safe = []
    per_method_evidence = []

    # Only consider methods that were actually probed. A method absent from
    # the map was never tested — it is NOT an "unverified error" and must not
    # drive a fail-closed Unsafe verdict.
    _ORDER = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')
    present = [m for m in _ORDER if m in method_map]
    present += [m for m in method_map if m not in _ORDER]

    for method in present:
        r = method_map.get(method, {})
        st = r.get('status')
        body = r.get('body', '') or ''
        # Normalize: bytes for trivial/snippet checks, clean text for regex
        if isinstance(body, bytes):
            body_bytes = body
            btext = body.decode('utf-8', 'replace')
        else:
            body_bytes = (body or '').encode('utf-8')
            btext = str(body or '')
        length = r.get('length') or 0
        waf_flag = bool(r.get('waf'))
        content_type = r.get('content_type', '')

        # Error / timeout
        if st is None:
            unverified.append(method)
            per_method_evidence.append(
                f'{method}->ERR({r.get("err_type", "UNKNOWN")})')
            continue

        # WAF block
        if waf_flag:
            waf_2xx.append(method)
            per_method_evidence.append(f'{method}->{st} [WAF]')
            continue

        # Auth enforced
        if st in (401, 403):
            confirmed_safe.append(f'{method}->{st}(auth)')
            per_method_evidence.append(f'{method}->{st} [AUTH]')
            continue

        # 2xx
        if 200 <= st < 300:
            if st == 204 or length == 0:
                confirmed_safe.append(f'{method}->{st}(empty)')
                per_method_evidence.append(f'{method}->{st}')
                continue

            bt = classify_body_type(content_type, body)
            if is_trivial_body(body, bt, path):
                confirmed_safe.append(f'{method}->{st}(trivial)')
                per_method_evidence.append(f'{method}->{st} [TRIV]')
                continue

            # Credential-gated 2xx
            cg = cred_gate_hits(btext)
            if cg:
                confirmed_safe.append(f'{method}->{st}(auth-gated:{",".join(cg)})')
                per_method_evidence.append(f'{method}->{st} [AUTH-GATED]')
                continue

            # Real data
            data_2xx.append((method, st, length, body_snippet(body_bytes, 200)))
            per_method_evidence.append(f'{method}->{st} [DATA {length}B]')
            continue

        # 3xx
        if 300 <= st < 400:
            loc = r.get('location', '')
            per_method_evidence.append(f'{method}->{st} [REDIRECT:{loc[:80]}]')
            # Redirect to admin/data path = suspected
            if re.search(r'/admin|/data|/export|/download|/internal', loc, re.I):
                data_2xx.append((method, st, length, f'Redirects to: {loc[:200]}'))
            continue

        # 405
        if st == 405:
            confirmed_safe.append(f'{method}->{st}(method)')
            per_method_evidence.append(f'{method}->{st}')
            continue

        # 400 — scan for leaks (fail-closed)
        if st == 400:
            lh = leak_hits(btext)
            param_hints = param_contract_hints(btext)
            if lh or param_hints:
                labels = list(lh)
                if param_hints:
                    labels.append('param-contract')
                leaks_all += labels
                detail = ''
                if param_hints:
                    detail = f':{",".join(param_hints[:5])}'
                per_method_evidence.append(
                    f'{method}->{st} [LEAK:{",".join(labels)}{detail}]')
            else:
                confirmed_safe.append(f'{method}->{st}(validation)')
                per_method_evidence.append(f'{method}->{st}')
            continue

        # 404 — scan for leaks
        if st == 404:
            lh = leak_hits(btext)
            if lh:
                leaks_all += lh
                per_method_evidence.append(f'{method}->{st} [LEAK:{",".join(lh)}]')
            else:
                confirmed_safe.append(f'{method}->{st}(notfound)')
                per_method_evidence.append(f'{method}->{st}')
            continue

        # Other 4xx
        if 400 <= st < 500:
            lh = leak_hits(btext)
            if lh:
                leaks_all += lh
                per_method_evidence.append(f'{method}->{st} [LEAK:{",".join(lh)}]')
            else:
                confirmed_safe.append(f'{method}->{st}')
                per_method_evidence.append(f'{method}->{st}')
            continue

        # 5xx
        if st >= 500:
            lh = leak_hits(btext)
            if lh:
                leaks_all += lh
                per_method_evidence.append(f'{method}->{st} [LEAK:{",".join(lh)}]')
            else:
                confirmed_safe.append(f'{method}->{st}')
                per_method_evidence.append(f'{method}->{st}')
            continue

    # ---- Decision (fail-closed) ----
    verdict, sub = 'SAFE', ''

    if data_2xx:
        verdict, sub = 'Unsafe', 'data'
    elif leaks_all:
        verdict, sub = 'Unsafe', 'leak'
    elif unverified and not confirmed_safe:
        verdict, sub = 'Unsafe', 'unverified-error'
    elif waf_2xx and not confirmed_safe and not data_2xx:
        verdict, sub = 'Unsafe', 'suspected'
    elif unverified:
        verdict, sub = 'Unsafe', 'unverified-error'

    # Must have at least one positive safe reason
    if verdict == 'SAFE' and not confirmed_safe:
        verdict, sub = 'Unsafe', 'suspected'

    evidence = '; '.join(per_method_evidence)
    return verdict, sub, evidence, sorted(set(leaks_all)), data_2xx
