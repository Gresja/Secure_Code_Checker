"""
Sample: safe path handling (reference implementation).

Purpose: basename + resolve + base-dir check; expected 0 issues.
Contrasts with: samples/path_traversal_vulnerable.py
"""
import os
from pathlib import Path

UPLOAD_BASE = Path("/var/app/uploads").resolve()


def read_user_file(filename):
    safe_name = os.path.basename(filename)
    target = (UPLOAD_BASE / safe_name).resolve()

    if not str(target).startswith(str(UPLOAD_BASE)):
        raise ValueError("Access denied: path traversal detected.")

    with open(target, "r", encoding="utf-8") as f:
        return f.read()


def delete_upload(filename):
    safe_name = os.path.basename(filename)
    target = (UPLOAD_BASE / safe_name).resolve()

    if not str(target).startswith(str(UPLOAD_BASE)):
        raise ValueError("Access denied: path traversal detected.")

    target.unlink()
