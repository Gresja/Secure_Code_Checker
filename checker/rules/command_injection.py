import ast


class CommandInjectionChecker(ast.NodeVisitor):
    DANGEROUS_OS_CALLS = {"system", "popen"}
    DANGEROUS_SUBPROCESS_CALLS = {"call", "check_call", "check_output", "Popen", "run"}

    def __init__(self, issues_callback):
        self.issues_callback = issues_callback

    def _is_os_command_call(self, node):
        return (
            isinstance(node.func, ast.Attribute) and
            isinstance(node.func.value, ast.Name) and
            node.func.value.id == "os" and
            node.func.attr in self.DANGEROUS_OS_CALLS
        )

    def _uses_shell_true(self, node):
        return any(
            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in node.keywords
        )

    def _is_subprocess_shell_call(self, node):
        return (
            isinstance(node.func, ast.Attribute) and
            isinstance(node.func.value, ast.Name) and
            node.func.value.id == "subprocess" and
            node.func.attr in self.DANGEROUS_SUBPROCESS_CALLS and
            self._uses_shell_true(node)
        )

    def visit_Call(self, node):
        if self._is_os_command_call(node) or self._is_subprocess_shell_call(node):
            self.issues_callback(
                rule_name="COMMAND_INJECTION_RISK",
                description=(
                    "Potentially unsafe command execution detected. "
                    "Avoid shell execution with untrusted input."
                ),
                line_number=node.lineno,
                severity="CRITICAL"
            )
        self.generic_visit(node)
