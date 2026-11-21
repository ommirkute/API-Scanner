"""API Scanner — unauthenticated API exposure assessment tool.

Scans API endpoints for unauthenticated data exposure, WAF bypasses,
and information disclosure. Fail-closed by default: every response is
inspected before being marked safe.

Modules:
    scanner      Core scan engine (probe, classify, consolidate, live workbook)
    classifiers  Classification rules (fail-closed, leak patterns, credential gates)
    waf_bypass   WAF bypass battery with path-traversal variants
    reporter     Excel workbook builder (all sheets)
    utils        Shared helpers (sanitize, patterns, body parsing, error typing)
"""

__version__ = '2.0.0'
__author__ = 'API Scanner'

from .utils import (
    LEAK_PATTERNS,
    CRED_GATE_PATTERNS,
    WAF_MARKERS,
    WAF_STRONG_MARKERS,
    WAF_HTML_ONLY_MARKERS,
    HEALTH_RE,
    sanitize,
    api_path,
    classify_body_type,
    is_trivial_body,
    is_waf_block,
    error_type_label,
    leak_hits,
    cred_gate_hits,
    param_contract_hints,
    body_snippet,
)
from .classifiers import classify, classify_endpoint
from .scanner import (
    load_endpoints,
    load_endpoints_xlsx,
    probe,
    scan,
    retry_errors,
    consolidate,
    write_workbook,
    tcp_precheck,
    LiveWorkbookWriter,
    DEFAULT_METHODS,
)
from .waf_bypass import run_bypass_battery, path_traversal_variants

__all__ = [
    # input
    'load_endpoints', 'load_endpoints_xlsx',
    # scan
    'probe', 'scan', 'retry_errors', 'consolidate', 'write_workbook',
    'tcp_precheck', 'LiveWorkbookWriter', 'DEFAULT_METHODS',
    # classification
    'classify', 'classify_endpoint',
    # WAF bypass
    'run_bypass_battery', 'path_traversal_variants',
    # helpers
    'sanitize', 'api_path', 'classify_body_type', 'is_trivial_body',
    'is_waf_block', 'error_type_label', 'leak_hits', 'cred_gate_hits',
    'param_contract_hints', 'body_snippet',
    # constants
    'LEAK_PATTERNS', 'CRED_GATE_PATTERNS', 'WAF_MARKERS',
    'WAF_STRONG_MARKERS', 'WAF_HTML_ONLY_MARKERS', 'HEALTH_RE',
]
