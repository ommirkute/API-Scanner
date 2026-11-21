#!/usr/bin/env python3
"""WAF bypass battery — CLI entry point.

Usage:
    python3 run_bypass.py scan_results.raw.json -o bypass.json
    python3 run_bypass.py scan_results.raw.json -o bypass.json --no-traversal
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api_scanner.waf_bypass import main as bypass_main

if __name__ == '__main__':
    bypass_main()
