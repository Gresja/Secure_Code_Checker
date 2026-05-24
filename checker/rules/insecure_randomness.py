import ast


class InsecureRandomnessChecker(ast.NodeVisitor):
    """
    Detects use of the 'random' module for security-sensitive purposes.

    Python's random module uses a Mersenne Twister PRNG which is not
    cryptographically secure. An attacker who observes enough output can
    predict future values. Use the 'secrets' module instead for:
      - tokens, session IDs, password reset links
      - API keys, nonces, CSRF tokens
    """

    # random functions commonly misused for security values
    INSECURE_FUNCS = {
        "random", "randint", "randrange", "choice",
        "choices", "sample", "uniform", "getrandbits"
    }

    # variable names that suggest a security context
    SECURITY_NAMES = (
        "token", "secret", "key", "password", "passwd", "pwd",
        "session", "nonce", "csrf", "otp", "salt", "pin", "auth",
        "id", "uuid", "code", "hash"
    )

    def __init__(self, issues_callback):
        self.issues_callback = issues_callback
        self._random_alias = set()   # tracks `import random as X` aliases
        self._in_security_context = False

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == "random":
                name = alias.asname if alias.asname else "random"
                self._random_alias.add(name)
        self.generic_visit(node)

    def _is_security_assign(self, node):
        """Return True if the parent assignment target looks security-related."""
        if not isinstance(node, ast.Call):
            return False
        return False

    def _target_looks_sensitive(self, targets):
        for t in targets:
            name = ""
            if isinstance(t, ast.Name):
                name = t.id
            elif isinstance(t, ast.Attribute):
                name = t.attr
            if any(s in name.lower() for s in self.SECURITY_NAMES):
                return True
        return False

    def visit_Assign(self, node):
        if self._target_looks_sensitive(node.targets):
            if isinstance(node.value, ast.Call):
                module, attr = self._call_parts(node.value)
                if module in self._random_alias and attr in self.INSECURE_FUNCS:
                    self.issues_callback(
                        rule_name="INSECURE_RANDOMNESS",
                        description=(
                            f"random.{attr}() is not cryptographically secure and "
                            "should not be used for security-sensitive values. "
                            "Use the 'secrets' module instead."
                        ),
                        line_number=node.lineno,
                        severity="HIGH"
                    )
        self.generic_visit(node)

    def visit_Call(self, node):
        module, attr = self._call_parts(node)
        if module in self._random_alias and attr in self.INSECURE_FUNCS:
            # Flag every use — let the assignment check add the context
            self.issues_callback(
                rule_name="INSECURE_RANDOMNESS",
                description=(
                    f"random.{attr}() produces predictable values and must not be "
                    "used for tokens, keys, session IDs, or any security purpose. "
                    "Replace with secrets.token_hex(), secrets.token_urlsafe(), or secrets.choice()."
                ),
                line_number=node.lineno,
                severity="HIGH"
            )
        self.generic_visit(node)

    def _call_parts(self, node):
        if (
            isinstance(node.func, ast.Attribute) and
            isinstance(node.func.value, ast.Name)
        ):
            return node.func.value.id, node.func.attr
        return "", ""
