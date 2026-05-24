"""
hardcoded_credentials.py — Hardcoded secrets rule (HardcodedCredentialsChecker).

Rule ID: HARDCODED_CREDENTIAL | Severity: CRITICAL

Purpose:
    Detect passwords, API keys, tokens, and similar secrets stored as string literals.

What it does:
    Flags Assign nodes to sensitive variable/attribute names and dict keys with
    non-empty string values; may also flag secret-shaped values in dictionaries.
"""
import ast
import re

class HardcodedCredentialsChecker(ast.NodeVisitor):
    SENSITIVE_NAMES = (
        "password", "passwd", "pwd", "secret", "api_key",
        "apikey", "token", "auth", "credentials", "private_key"
    )

    SECRET_PATTERNS = [
        r"^[A-Za-z0-9+/]{20,}={0,2}$",
        r"sk-[A-Za-z0-9]{10,}",
        r"Bearer\s+[A-Za-z0-9\-_]{10,}",
        r"[A-Za-z0-9]{32,}",
    ]

    def __init__(self, issues_callback):
        self.issues_callback = issues_callback

    def _is_sensitive_name(self, name):
        name_lower = name.lower()
        return any(sensitive in name_lower for sensitive in self.SENSITIVE_NAMES)

    def _is_secret_value(self, value):
        if not isinstance(value, str) or len(value) < 6:
            return False
        return any(re.search(pattern, value) for pattern in self.SECRET_PATTERNS)

    def _report(self, name, node):
        self.issues_callback(
            rule_name="HARDCODED_CREDENTIAL",
            description=(
                f"Hardcoded credential found in '{name}'. "
                "Move secrets to environment variables or a secrets manager."
            ),
            line_number=node.lineno,
            severity="CRITICAL"
        )

    def _is_non_empty_string(self, node):
        return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.strip()

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                if self._is_sensitive_name(target.id) and self._is_non_empty_string(node.value):
                    self._report(f"variable '{target.id}'", node)
            elif isinstance(target, ast.Attribute):
                if self._is_sensitive_name(target.attr) and self._is_non_empty_string(node.value):
                    self._report(f"attribute '{target.attr}'", node)
        self.generic_visit(node)

    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue

            key_name = key.value
            if self._is_sensitive_name(key_name) and self._is_non_empty_string(value):
                self._report(f"dictionary key '{key_name}'", value)
            elif self._is_secret_value(getattr(value, "value", None)):
                self._report(f"dictionary value for '{key_name}'", value)
        self.generic_visit(node)
