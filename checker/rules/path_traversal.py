"""
path_traversal.py — Path traversal rule (PathTraversalChecker).

Rule ID: PATH_TRAVERSAL | Severity: HIGH

Purpose:
    Detect file paths built from user-controlled input (directory escape attacks).

What it does:
    Pass 1: mark variables assigned from input() or request-like sources as tainted.
    Pass 2: flag open(), os.*, os.path.join, and path concatenation using tainted data.
"""
import ast


class PathTraversalChecker(ast.NodeVisitor):
    """
    Detects file-path construction that uses user-supplied input directly.

    Tracks variables assigned from user-input sources (input(), request.args,
    etc.) across the whole module, then flags any path sink (open, os.remove,
    os.path.join, etc.) that uses one of those tainted variables.
    """

    USER_INPUT_CALLS = {
        "input",                              # CLI input()
    }

    USER_INPUT_ATTRS = {
        "request", "form", "args", "json",
        "data", "files", "environ",           # web request / env sources
    }

    PATH_SINKS      = {"open", "listdir", "makedirs", "remove", "rmdir", "stat", "access"}
    OS_PATH_SINKS   = {"join", "abspath", "realpath", "exists", "isfile", "isdir"}

    def __init__(self, issues_callback):
        self.issues_callback = issues_callback
        self._tainted: set[str] = set()      # variable names holding user input

    # ── Pass 1: collect tainted variable names ────────────────────────────────

    def visit_Module(self, node):
        """Two-pass: first collect tainted vars, then check sinks."""
        # collect taint
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                if self._expr_is_tainted(child.value):
                    for t in child.targets:
                        if isinstance(t, ast.Name):
                            self._tainted.add(t.id)

        # check sinks
        self.generic_visit(node)

    # ── Taint helpers ─────────────────────────────────────────────────────────

    def _expr_is_tainted(self, node):
        """Return True if node directly produces or contains user input."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name) and child.func.id in self.USER_INPUT_CALLS:
                    return True
                if (
                    isinstance(child.func, ast.Attribute) and
                    isinstance(child.func.value, ast.Name) and
                    child.func.value.id in self.USER_INPUT_ATTRS
                ):
                    return True
            if (
                isinstance(child, ast.Attribute) and
                isinstance(child.value, ast.Name) and
                child.value.id in self.USER_INPUT_ATTRS
            ):
                return True
        return False

    def _node_is_tainted(self, node):
        """Return True if node uses a tainted variable or a direct user-input source."""
        if self._expr_is_tainted(node):
            return True
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self._tainted:
                return True
        return False

    # ── Sink visitors ─────────────────────────────────────────────────────────

    def _report(self, node):
        self.issues_callback(
            rule_name="PATH_TRAVERSAL",
            description=(
                "User-controlled input is used to construct a file path. "
                "An attacker can supply '../' sequences to read or write "
                "files outside the intended directory. "
                "Sanitize with os.path.basename() and verify the resolved "
                "path starts inside the allowed base directory."
            ),
            line_number=node.lineno,
            severity="HIGH"
        )

    def visit_Call(self, node):
        func = node.func

        # open(tainted, ...)
        if isinstance(func, ast.Name) and func.id == "open":
            if node.args and self._node_is_tainted(node.args[0]):
                self._report(node)

        # os.<sink>(tainted, ...)
        elif (
            isinstance(func, ast.Attribute) and
            isinstance(func.value, ast.Name) and
            func.value.id == "os" and
            func.attr in self.PATH_SINKS
        ):
            if node.args and self._node_is_tainted(node.args[0]):
                self._report(node)

        # os.path.<sink>(..., tainted, ...)
        elif (
            isinstance(func, ast.Attribute) and
            isinstance(func.value, ast.Attribute) and
            isinstance(func.value.value, ast.Name) and
            func.value.value.id == "os" and
            func.value.attr == "path" and
            func.attr in self.OS_PATH_SINKS
        ):
            for arg in node.args:
                if self._node_is_tainted(arg):
                    self._report(node)
                    break

        self.generic_visit(node)

    def visit_BinOp(self, node):
        """Catch '/uploads/' + tainted_var string concatenation."""
        if isinstance(node.op, ast.Add):
            if self._node_is_tainted(node.left) or self._node_is_tainted(node.right):
                for side in (node.left, node.right):
                    if isinstance(side, ast.Constant) and isinstance(side.value, str):
                        val = side.value
                        if "/" in val or "\\" in val or val.startswith("."):
                            self._report(node)
                            break
        self.generic_visit(node)
