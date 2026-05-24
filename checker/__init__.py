"""
checker/ — Core analysis package.

Purpose:
    Hold the scanner engine (parser), report builder (reporter), and rule modules.

What it does:
    - Exports CodeAnalyzer from parser.py for use by main.py and web_app.py.
    - Rule implementations live in checker/rules/ and are wired in parser.py.

Files:
    parser.py   — loads source, runs AST rules, collects issues
    reporter.py — builds JSON/HTML reports and dynamic guidance
    rules/      — one AST visitor per vulnerability type
"""
from .parser import CodeAnalyzer
