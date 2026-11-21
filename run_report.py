#!/usr/bin/env python3
"""Report builder — CLI entry point.

Usage:
    python -m api_scanner.reporter scan_results.raw.json -o results.xlsx
    python -m api_scanner.reporter scan_results.raw.json -o results.xlsx --fail-closed
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api_scanner.reporter import main as report_main

if __name__ == '__main__':
    report_main()
