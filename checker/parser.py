import ast
import logging
from .rules import (
    SQLInjectionChecker,
    HardcodedCredentialsChecker,
    UnsafeFileHandlingChecker,
    EvalUsageChecker,
    WeakHashingChecker,
    CommandInjectionChecker,
    InsecureDeserializationChecker,
    InsecureRandomnessChecker,
    PathTraversalChecker,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class CodeAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.issues = []
        self.tree = None
        self.source_lines = []

    def load_file(self):
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                source = f.read()
            self.load_source(source, self.filepath)
            logger.info(f"Successfully parsed: {self.filepath}")
        except FileNotFoundError:
            logger.error(f"File not found: {self.filepath}")
            raise
        except SyntaxError as e:
            logger.error(f"Syntax error in file: {e}")
            raise

    def load_source(self, source, display_name=None):
        """Load source code directly, useful for web uploads or pasted code."""
        if display_name:
            self.filepath = display_name
        self.source_lines = source.splitlines()
        self.tree = ast.parse(source, filename=self.filepath)

    def add_issue(self, rule_name, description, line_number, severity="HIGH"):
        source_line = ""
        if line_number and 1 <= line_number <= len(self.source_lines):
            source_line = self.source_lines[line_number - 1].strip()

        issue = {
            "rule": rule_name,
            "description": description,
            "line": line_number,
            "severity": severity,
            "file": self.filepath,
            "code": source_line
        }
        self.issues.append(issue)
        logger.warning(f"[{severity}] {rule_name} at line {line_number}")

    def run_checks(self):
        if self.tree is None:
            logger.error("No AST loaded. Run load_file() first.")
            return

        rules = [
            SQLInjectionChecker(self.add_issue),
            HardcodedCredentialsChecker(self.add_issue),
            UnsafeFileHandlingChecker(self.add_issue),
            EvalUsageChecker(self.add_issue),
            WeakHashingChecker(self.add_issue),
            CommandInjectionChecker(self.add_issue),
            InsecureDeserializationChecker(self.add_issue),
            InsecureRandomnessChecker(self.add_issue),
            PathTraversalChecker(self.add_issue),
        ]

        for rule in rules:
            rule.visit(self.tree)

        logger.info(f"Checks complete. {len(self.issues)} issue(s) found.")

    def get_issues(self):
        return self.issues