import ast

class EvalUsageChecker(ast.NodeVisitor):
    """
    Detects calls to eval() which can execute arbitrary code
    and is a critical security risk if used with untrusted input.
    """

    def __init__(self, issues_callback):
        self.issues_callback = issues_callback

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Name) and
            node.func.id == "eval"
        ):
            self.issues_callback(
                rule_name="EVAL_USAGE",
                description=(
                    "Use of eval() detected. eval() executes arbitrary code and "
                    "is dangerous when used with untrusted input. "
                    "Use ast.literal_eval() for safe expression evaluation."
                ),
                line_number=node.lineno,
                severity="CRITICAL"
            )
        self.generic_visit(node)