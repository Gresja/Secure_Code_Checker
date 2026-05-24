"""
insecure_deserialization.py — Insecure deserialization rule (InsecureDeserializationChecker).

Rule ID: INSECURE_DESERIALIZATION | Severity: CRITICAL (pickle) / HIGH (yaml)

Purpose:
    Detect deserialization that can execute code or instantiate arbitrary objects.

What it does:
    Flags pickle.loads/load/Unpickler and yaml.load without a safe Loader.
    Ignores yaml.safe_load and Loader=SafeLoader.
"""
import ast


class InsecureDeserializationChecker(ast.NodeVisitor):
    """
    Detects use of insecure deserialization functions.

    - pickle.loads / pickle.load: can execute arbitrary Python when loading
      untrusted data.
    - yaml.load without an explicit safe Loader: PyYAML will construct
      arbitrary Python objects by default.
    """

    PICKLE_DANGER = {"loads", "load", "Unpickler"}
    YAML_DANGER   = {"load"}

    def __init__(self, issues_callback):
        self.issues_callback = issues_callback

    def _module_attr(self, node):
        """Return (module, attr) if node.func is a dotted call like mod.attr()."""
        if (
            isinstance(node.func, ast.Attribute) and
            isinstance(node.func.value, ast.Name)
        ):
            return node.func.value.id, node.func.attr
        return None, None

    def _yaml_uses_safe_loader(self, node):
        """Return True when yaml.load is called with Loader= a known safe class."""
        safe_loaders = {"SafeLoader", "CSafeLoader", "BaseLoader"}
        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute):
                    return kw.value.attr in safe_loaders
                if isinstance(kw.value, ast.Name):
                    return kw.value.id in safe_loaders
        return False

    def visit_Call(self, node):
        module, attr = self._module_attr(node)

        if module == "pickle" and attr in self.PICKLE_DANGER:
            self.issues_callback(
                rule_name="INSECURE_DESERIALIZATION",
                description=(
                    f"pickle.{attr}() deserializes arbitrary Python objects. "
                    "Untrusted pickle data can execute code during loading. "
                    "Use JSON or another safe format for untrusted input."
                ),
                line_number=node.lineno,
                severity="CRITICAL"
            )

        elif module == "yaml" and attr in self.YAML_DANGER:
            if not self._yaml_uses_safe_loader(node):
                self.issues_callback(
                    rule_name="INSECURE_DESERIALIZATION",
                    description=(
                        "yaml.load() without a safe Loader can instantiate arbitrary "
                        "Python objects. Pass Loader=yaml.SafeLoader or use yaml.safe_load()."
                    ),
                    line_number=node.lineno,
                    severity="HIGH"
                )

        self.generic_visit(node)
