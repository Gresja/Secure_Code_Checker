"""
Sample: safe expression handling (reference implementation).

Purpose: ast.literal_eval instead of eval; expected 0 issues.
Contrasts with: samples/eval_vulnerable.py
"""
import ast


def parse_literal(expression):
    """Safely parse a Python literal (numbers, strings, lists, dicts)."""
    return ast.literal_eval(expression)


def calculate_two_numbers(a, b, operator):
    if operator == "+":
        return a + b
    if operator == "-":
        return a - b
    raise ValueError("Unsupported operator")
