"""
checker/rules/ — Security rule registry.

Purpose:
    Export all AST-based rule checker classes for use in parser.py.

What it does:
    Each module defines one NodeVisitor that detects a vulnerability category
    and reports issues via the callback passed from CodeAnalyzer.add_issue().

Exported checkers:
    SQLInjectionChecker, HardcodedCredentialsChecker, UnsafeFileHandlingChecker,
    EvalUsageChecker, WeakHashingChecker, CommandInjectionChecker,
    InsecureDeserializationChecker, InsecureRandomnessChecker, PathTraversalChecker
"""
from .sql_injection import SQLInjectionChecker
from .hardcoded_credentials import HardcodedCredentialsChecker
from .unsafe_file import UnsafeFileHandlingChecker
from .eval_usage import EvalUsageChecker
from .weak_hashing import WeakHashingChecker
from .command_injection import CommandInjectionChecker
from .insecure_deserialization import InsecureDeserializationChecker
from .insecure_randomness import InsecureRandomnessChecker
from .path_traversal import PathTraversalChecker