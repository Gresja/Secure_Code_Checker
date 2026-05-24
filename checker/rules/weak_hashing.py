"""
weak_hashing.py — Weak hashing rule (WeakHashingChecker).

Rule ID: WEAK_HASHING_ALGORITHM | Severity: HIGH

Purpose:
    Detect MD5 and SHA1 usage via hashlib (collision-prone for security use).

What it does:
    Flags hashlib.md5(), hashlib.sha1(), and hashlib.new('md5'/'sha1').
    Recommends SHA-256/SHA-3 or password-specific libraries (bcrypt, argon2).
"""
import ast

class WeakHashingChecker(ast.NodeVisitor):
    """
    Detects use of weak cryptographic hash functions MD5 and SHA1.
    These are considered insecure for password hashing and
    integrity verification due to known collision vulnerabilities.
    """

    WEAK_ALGORITHMS = ("md5", "sha1", "sha-1")

    def __init__(self, issues_callback):
        self.issues_callback = issues_callback

    def _is_weak_hashlib_call(self, node):
        """Detect hashlib.md5() or hashlib.sha1() calls."""
        return (
            isinstance(node.func, ast.Attribute) and
            isinstance(node.func.value, ast.Name) and
            node.func.value.id == "hashlib" and
            node.func.attr.lower() in self.WEAK_ALGORITHMS
        )

    def _is_weak_new_call(self, node):
        """Detect hashlib.new('md5') or hashlib.new('sha1') calls."""
        if not (
            isinstance(node.func, ast.Attribute) and
            isinstance(node.func.value, ast.Name) and
            node.func.value.id == "hashlib" and
            node.func.attr == "new"
        ):
            return False
        # Check first argument is a weak algorithm name string
        if node.args and isinstance(node.args[0], ast.Constant):
            return node.args[0].value.lower() in self.WEAK_ALGORITHMS
        return False

    def visit_Call(self, node):
        if self._is_weak_hashlib_call(node) or self._is_weak_new_call(node):
            self.issues_callback(
                rule_name="WEAK_HASHING_ALGORITHM",
                description=(
                    "Weak hashing algorithm detected (MD5 or SHA1). "
                    "These are vulnerable to collision attacks. "
                    "Use SHA-256 or SHA-3 instead: hashlib.sha256()."
                ),
                line_number=node.lineno,
                severity="HIGH"
            )
        self.generic_visit(node)