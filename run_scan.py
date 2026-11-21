#!/usr/bin/env python3
"""API Scanner — CLI entry point.

Usage examples:

    # Basic scan (live sheet updates in real time)
    python3 run_scan.py endpoints.txt -o results.xlsx

    # From inventory workbook with fail-closed
    python3 run_scan.py inventory.xlsx -o results.xlsx --fail-closed -w 24 -t 30

    # With TCP precheck (writes results_unreachable.txt, adds N/A rows)
    python3 run_scan.py endpoints.txt -o results.xlsx --precheck

    # Disable the live-updating sheet (plain Result sheet only)
    python3 run_scan.py endpoints.txt -o results.xlsx --no-live-sheet

    # Re-render the workbook from the raw cache (same output path stem)
    python3 run_scan.py endpoints.txt -o results.xlsx --from-cache

    # WAF bypass battery (separate entry point)
    python3 run_bypass.py results.raw.json -o bypass.json

    # Build the full report workbook (separate entry point)
    python3 run_report.py results.raw.json -o report.xlsx
"""

import sys
import os

# Ensure the package directory is on the path when run as a script
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api_scanner.scanner import main as scan_main

if __name__ == '__main__':
    scan_main()
