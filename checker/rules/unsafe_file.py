"""
unsafe_file.py — Unsafe file handling rule (UnsafeFileHandlingChecker).

Rule ID: UNSAFE_FILE_HANDLING | Severity: MEDIUM

Purpose:
    Detect open() calls that are not protected by a context manager or try/except.

What it does:
    Tracks visit_With and visit_Try scope; flags bare open() calls that may leak
    file handles or leave partial writes on errors.
"""
import ast

class UnsafeFileHandlingChecker(ast.NodeVisitor):
    def __init__(self, issues_callback):
        self.issues_callback = issues_callback
        self._in_try_block = False
        self._in_with_block = False

    def _is_open_call(self, node):
        return (
            isinstance(node, ast.Call) and
            isinstance(node.func, ast.Name) and
            node.func.id == "open"
        )

    def visit_With(self, node):
        prev = self._in_with_block
        self._in_with_block = True
        self.generic_visit(node)
        self._in_with_block = prev

    def visit_Try(self, node):
        prev = self._in_try_block
        self._in_try_block = True
        self.generic_visit(node)
        self._in_try_block = prev

    def visit_Call(self, node):
        if self._is_open_call(node):
            if not self._in_try_block and not self._in_with_block:
                self.issues_callback(
                    rule_name="UNSAFE_FILE_HANDLING",
                    description=(
                        "File opened without exception handling. "
                        "Use 'with open(...) as f' or wrap in a try/except block."
                    ),
                    line_number=node.lineno,
                    severity="MEDIUM"
                )
        self.generic_visit(node)
