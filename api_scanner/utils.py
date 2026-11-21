#!/usr/bin/env python3
"""Shared constants and helpers for the API Scanner."""

import json
import re
import xml.etree.ElementTree as ET

# ---- WAF block-page signatures ----
# Two tiers to avoid false "Safe (WAF)" on legitimate API data:
#
#   WAF_STRONG_MARKERS: vendor-specific strings that essentially never appear
#   inside a real API JSON/XML payload. Match on ANY 2xx body.
#
#   WAF_HTML_ONLY_MARKERS: generic words (proxy, firewall, azure, access denied)
#   that CAN appear in legitimate data. These only count as WAF when the
#   response is actually an HTML block page (Content-Type: text/html or body
#   starts with '<'). A 200 JSON payload containing {"proxy": "10.0.0.1"}
#   is DATA, not a WAF block.

WAF_STRONG_MARKERS = (
    # F5 / iBot / ASM
    b'request rejected', b'your support id', b'imperva', b'f5 networks',
    # Akamai
    b'akamai-gtm', b'edgecast', b'tlu.akamai',
    # Cloudflare
    b'cloudflare-ray-id', b'cf-ray', b'challenge verify',
    # Sucuri
    b'sucuri website firewall', b'sucuri.net',
    # AWS WAF
    b'awswebapplicationfirewall', b'awswaf',
    # Barracuda
    b'barracuda networks', b'barracuda response',
    # Fortinet
    b'fortinet', b'fortigate', b'fortiweb',
    # ModSecurity
    b'mod_security', b'modsecurity',
)

WAF_HTML_ONLY_MARKERS = (
    # F5 / iBot / ASM
    b'access denied', b'access violation', b'denied at the firewall',
    # Akamai
    b'akamai', b'akamai cloud', b'reference #',
    # Cloudflare
    b'cloudflare', b'attention required!', b'ray id', b'cloudflare inc',
    # Sucuri
    b'sucuri',
    # AWS WAF
    b'aws waf',
    # Azure / Front Door / Application Gateway
    b'front door', b'application gateway', b'microsoft-httpapi',
    # Barracuda
    b'barracuda',
    # generic
    b'blocked by', b'security check', b'firewall', b'proxy', b'challenge page',
    # Zuul / Zuul-gateway style auth errors
    b'missing credentials', b'zuul',
)

# Compatibility union (used for legacy caches / standalone checks).
WAF_MARKERS = WAF_STRONG_MARKERS + WAF_HTML_ONLY_MARKERS


def is_waf_block(status, body, content_type=''):
    """Two-tier WAF block-page detection.

    Strong markers match on any 2xx body. Weak markers only match when the
    response is an HTML block page (Content-Type contains 'html', or the body
    starts with '<' / '<!doctype'). Prevents JSON/XML data containing words
    like 'proxy' or 'azure' from being misclassified as WAF-blocked.
    """
    if status is None or not (200 <= status < 300):
        return False
    if not body:
        return False
    if isinstance(body, str):
        body = body.encode('utf-8', 'replace')
    low = body[:2000].lower()
    if any(m in low for m in WAF_STRONG_MARKERS):
        return True
    # Weak markers only count on real HTML block pages. XML (SOAP/API) starts
    # with '<?xml' or '<' too but is data — exclude it.
    ct = (content_type or '').lower()
    head = low.lstrip()
    looks_html = ('html' in ct
                  or head.startswith(b'<!doctype')
                  or head.startswith(b'<html'))
    if looks_html and any(m in low for m in WAF_HTML_ONLY_MARKERS):
        return True
    return False

# ---- Leak patterns for error-body scanning ----
# Each entry: (compiled_regex, label). Scanned against 4xx/5xx bodies and
# 400 validation-error bodies.
LEAK_PATTERNS = [
    # Stack traces
    (r'traceback|at com\.|at org\.|java\.lang\.|caused by|'
     r'\.php on line|\\.py\"|File ".+?\", line', 'stack-trace'),
    # SQL
    (r'select .* from|sqlstate|sqlexception|syntax error|jdbc:|'
     r"you have an error in your sql syntax|mysql|postgresql|oracle|"
     r"sql server|\.net sql|oledb|odbc", 'sql-leak'),
    # Framework / ORM
    (r'org\.hibernate|com\.oracle\.jdbc|springframework|com\.wso2|'
     r'django\.core|flask\.|express\.|laravel|rails\.|'
     r'\.net framework|asp\.net|wcf\.', 'framework-leak'),
    # PII — email
    (r'"email"\s*:\s*"|\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', 'possible-pii-email'),
    # Secrets
    (r'\bpassword\b\s*[:=]|\bsecret\b\s*[:=]|\bbearer\s+[a-z0-9\-=._]{20,}|'
     r'api[_-]?key\s*[:=]|\btoken\s*[:=]', 'possible-secret'),
    # Version banners / infra disclosure
    (r'\b(Spring|Hibernate|Hibernate JPA|Oracle Database|MySQL|PostgreSQL|'
     r'Microsoft SQL|MongoDB|Redis|WCF|\.NET Framework|Apache Tomcat|Jetty|'
     r'WebSphere|WebLogic|JBoss|Grails|Kafka|nginx|Apache)\b', 'version-banner'),
    # DB driver disclosure
    (r'\bjdbc:|oracle\.jdbc|com\.mysql|postgresql|'
     r'system\.data\.sqlite|pyodbc|psycopg|mongo\.client', 'db-driver'),
]

# ---- Credential-gate phrases ----
# 2xx bodies containing these indicate the endpoint is gated behind credentials
# (returns 200 with a "User Id is required" message instead of 401).
CRED_GATE_PATTERNS = [
    (r"user\s*id\s*is\s*required", "user-id-required"),
    (r"password\s*is\s*required", "password-required"),
    (r"missing\s*credentials", "missing-credentials"),
    (r"api\s*authentication\s*failed", "api-auth-failed"),
    (r"authentication\s*required", "auth-required"),
    (r"authorization\s*required", "authorization-required"),
    (r"token\s*is\s*required", "token-required"),
    (r"login\s*required", "login-required"),
    (r"access\s*denied", "access-denied"),
    (r"not\s*authorized", "not-authorized"),
    (r"forbidden", "forbidden"),
    (r"invalid\s*credentials", "invalid-credentials"),
    (r"session\s*(expired|invalid|required)", "session-required"),
]

# ---- 400-body API-contract disclosure patterns ----
# 400 validation messages that reveal the API's parameter contract
# ("customerId is required", "additional parameter is required",
#  "missing field: X", "invalid value for: amount") disclose internals an
# attacker can exploit. In fail-closed mode these are Unsafe (leak).
# Group 1 = the named field/parameter, if capturable (used for display).
# "...: name" form: "missing field: amount", "invalid value for: amount",
# "required: customerId" — keyword (optionally with a filler noun) then a
# colon, then the disclosed field name.
PARAM_COLON_RE = re.compile(
    r'(?:missing|required|invalid|expected|additional\s+parameters?)'
    r'(?:\s+(?:field|parameter|property|value|argument|attribute))?'
    r'(?:\s+for)?\s*:\s*["\']?(\w+)', re.I)
# "name is required" form: "customerId is required", "User Id is required",
# "additional parameter is required" — the name immediately before
# "is/are required/missing".
PARAM_IS_REQ_RE = re.compile(
    r'([\w][\w\s\-]{0,24}?)\s+(?:is|are)\s+(?:required|missing|not\s+provided)',
    re.I)

# ---- Health endpoint regex ----
HEALTH_RE = re.compile(
    r'(/healthz?|/health[/\w]*|/readiness|/livez|/readyz|/actuator/health|/status'
    r'|/keep-?alive|/ping)$', re.I)

# ---- Illegal control chars for Excel ----
_ILLEGAL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def sanitize(text):
    """Strip characters that Excel forbids in cells."""
    if not text:
        return text
    return _ILLEGAL_RE.sub('', str(text))


def api_path(url):
    """(fqdn, api-path) for https://host/a/b -> ('host', '/a/b')."""
    m = re.search(r'//([^/]+)/?', url)
    fq = m.group(1) if m else ''
    return fq, url.split(fq, 1)[-1] if fq else url


def classify_body_type(content_type_header, body):
    """Return a human-readable body type label.

    Types: json, xml, html, form, text, binary, unknown
    Accepts bytes or str for `body`.
    """
    ct = (content_type_header or '').lower()
    if 'json' in ct or 'javascript' in ct:
        return 'json'
    if 'xml' in ct or 'soap' in ct:
        return 'xml'
    if 'html' in ct:
        return 'html'
    if 'form-urlencoded' in ct or 'x-www-form' in ct:
        return 'form'
    if 'text/plain' in ct or 'text/' in ct:
        return 'text'
    if 'octet-stream' in ct or 'image/' in ct or 'pdf' in ct:
        return 'binary'
    # Heuristic on the body head (bytes or str)
    if body:
        if isinstance(body, str):
            head = body[:200].lstrip()
            if head.startswith('{') or head.startswith('['):
                return 'json'
            if head.startswith('<html') or head.startswith('<!doctype'):
                return 'html'
            if head.startswith('<') or head.startswith('<?xml'):
                return 'xml'
        else:
            head = body[:200].lstrip()
            if head.startswith(b'{') or head.startswith(b'['):
                return 'json'
            if head.startswith(b'<html') or head.startswith(b'<!doctype'):
                return 'html'
            if head.startswith(b'<') or head.startswith(b'<?xml'):
                return 'xml'
    return 'unknown'


def is_trivial_body(body, body_type='unknown', path=''):
    """True if the response body carries no business data.

    Handles JSON, XML/SOAP, form-urlencoded, and health endpoints.
    Accepts bytes or str.
    """
    if body is None:
        return True
    if isinstance(body, str):
        body_bytes = body.encode('utf-8')
    else:
        body_bytes = body

    if not body_bytes:
        return True

    # Health / status endpoints are trivial by design regardless of body
    if path and HEALTH_RE.search(path):
        return True

    text = body_bytes.decode('utf-8', 'replace').strip()

    # Null / empty
    if text in ('', 'null'):
        return True

    # Trivial JSON
    if text in ('{}', '[]', '{"success":true}', '{"success": true}', 'pong',
                '{"ok":true}', '{"ok": true}', '{"status":"ok"}',
                '{"status":"success"}', 'true', 'false'):
        return True

    # JSON envelope with only trivial values.
    # A value that looks like PII (email '@') or an ID/record number
    # (6+ consecutive digits) is NOT trivial — flag it for review instead
    # of auto-Safe (fail-closed).
    _PII_RE = re.compile(r'@|\d{6,}')
    try:
        j = json.loads(text)
        if isinstance(j, dict):
            if len(j) == 0:
                return True
            if len(j) <= 4 and all(
                v in (None, True, False, '') or
                (isinstance(v, (int, float)) and v in (0, 1)) or
                (isinstance(v, str) and len(v) <= 40 and not _PII_RE.search(v))
                for v in j.values()
            ) and not any(
                isinstance(v, str) and _PII_RE.search(v) for v in j.values()
            ):
                return True
        if isinstance(j, list):
            # A non-empty list of records is data, not trivial
            if len(j) == 0:
                return True
        else:
            # scalar JSON: numbers / booleans / null / short strings
            if j in (None, True, False):
                return True
            if isinstance(j, (int, float)):
                return True
            if isinstance(j, str) and len(j) <= 40 and not _PII_RE.search(j):
                return True
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # XML / SOAP: check for Envelope with only status/fault nodes (no data)
    if body_type == 'xml':
        try:
            root = ET.fromstring(text)
            # SOAP Envelope -> Body -> Fault or Status only
            ns = {'s': 'http://schemas.xmlsoap.org/soap/envelope/'}
            body = root.find('.//s:Body', ns)
            if body is not None:
                children = [c for c in body]
                if len(children) == 1:
                    child = children[0]
                    tag = child.tag.split('}')[-1].lower() if '}' in child.tag else child.tag.lower()
                    if tag in ('fault', 'status', 'error', 'faultstring'):
                        return True
            # Plain XML with only <Status> or <Error>
            root_tag = root.tag.split('}')[-1].lower() if '}' in root.tag else root.tag.lower()
            if root_tag in ('status', 'error', 'fault'):
                return True
        except ET.ParseError:
            pass  # malformed XML -> not trivial

    # Form-urlencoded: all trivial key=value pairs
    if body_type == 'form':
        pairs = re.findall(r'([^&=]+)=([^&]*)', text)
        if pairs and all(
            v.strip() in ('', 'true', 'false', '1', '0') or len(v.strip()) <= 20
            for _, v in pairs
        ):
            return True

    return False


def error_type_label(exc):
    """Return a short human-readable error type from an exception."""
    name = type(exc).__name__
    mapping = {
        'ConnectionError': 'CONN',
        'ConnectionRefusedError': 'CONNREFUSED',
        'ConnectionResetError': 'RESET',
        'Timeout': 'TIMEOUT',
        'ReadTimeout': 'TIMEOUT',
        'ConnectTimeout': 'TIMEOUT',
        'SSLError': 'TLS',
        'CertificateError': 'TLS',
        'TooManyRedirects': 'REDIRECTS',
        'gaierror': 'DNS',
        'socket.gaierror': 'DNS',
        'HTTPError': 'HTTP',
        'URLRequired': 'BADURL',
        'MissingSchema': 'BADURL',
        'InvalidSchema': 'BADURL',
        'InvalidURL': 'BADURL',
    }
    for key, label in mapping.items():
        if key.lower() in name.lower():
            return label
    return name


def leak_hits(body_text):
    """Return list of leak-labels found in a body text string."""
    hits = []
    for pat, label in LEAK_PATTERNS:
        if re.search(pat, body_text, re.I):
            hits.append(label)
    return hits


def param_contract_hints(body_text):
    """Return field/parameter names disclosed by a 4xx validation-error body.

    Matches both "missing field: customerId" style messages and
    "customerId is required" style messages. Empty list = no contract
    disclosure.
    """
    text = str(body_text or '')
    hints = []
    for m in PARAM_COLON_RE.finditer(text):
        hints.append(m.group(1))
    for m in PARAM_IS_REQ_RE.finditer(text):
        name = m.group(1) if m.lastindex and m.lastindex >= 1 else 'parameter'
        # 'additional parameters is required' has no named field — group(1)
        # would capture "additional" — normalize to the generic label.
        if name.strip().lower() in ('additional', 'a', 'an'):
            name = 'parameter'
        hints.append(name.strip())
    return list(dict.fromkeys(hints))


def cred_gate_hits(body_text):
    """Return list of credential-gate labels found in a body text string."""
    hits = []
    for pat, label in CRED_GATE_PATTERNS:
        if re.search(pat, body_text, re.I):
            hits.append(label)
    return hits


def body_snippet(data, limit=400):
    """Return a readable snippet or a binary marker. Accepts bytes or str."""
    if not data:
        return ''
    if isinstance(data, str):
        text = data[:limit]
        return text
    head = data[:limit]
    text = head.decode('utf-8', 'replace')
    if b'\x00' in head or text.count('�') > max(3, len(head) // 50):
        return f'[binary {len(data)} bytes total]'
    return text
