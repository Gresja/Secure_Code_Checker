import ast

class SQLInjectionChecker(ast.NodeVisitor):
    SQL_KEYWORDS = ("select", "insert", "update", "delete", "drop", "where", "from")

    def __init__(self, issues_callback):
        self.issues_callback = issues_callback

    def _contains_sql(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            lower = node.value.lower()
            return any(keyword in lower for keyword in self.SQL_KEYWORDS)
        return False

    def _string_contains_sql(self, value):
        return isinstance(value, str) and any(keyword in value.lower() for keyword in self.SQL_KEYWORDS)

    def _report(self, node, pattern):
        self.issues_callback(
            rule_name="SQL_INJECTION_RISK",
            description=(
                f"Unsafe {pattern} in a SQL query detected. "
                "Use parameterized queries instead (e.g. cursor.execute(query, params))."
            ),
            line_number=node.lineno,
            severity="HIGH"
        )

    def visit_BinOp(self, node):
        if isinstance(node.op, ast.Add):
            if self._contains_sql(node.left) or self._contains_sql(node.right):
                self._report(node, "string concatenation")
        elif isinstance(node.op, ast.Mod):
            if self._contains_sql(node.left):
                self._report(node, "percent-formatting")
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        if any(self._string_contains_sql(value.value) for value in node.values if isinstance(value, ast.Constant)):
            self._report(node, "f-string interpolation")
        self.generic_visit(node)

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Attribute) and
            node.func.attr == "format" and
            self._contains_sql(node.func.value)
        ):
            self._report(node, "format() interpolation")
        self.generic_visit(node)
