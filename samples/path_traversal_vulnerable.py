# Intentionally vulnerable — path traversal examples

import os

UPLOAD_DIR = "/var/app/uploads/"
REPORTS_DIR = "/var/app/reports/"

# ── Vulnerable: open() with raw user input ────────────────────────────────────
def read_user_file():
    filename = input("Enter the filename to read: ")
    f = open("/var/app/files/" + filename, "r")   # ../../etc/passwd escapes the dir
    return f.read()

# ── Vulnerable: os.path.join with user input ──────────────────────────────────
def serve_report():
    filename = input("Enter report name: ")
    path = os.path.join(REPORTS_DIR, filename)    # os.path.join doesn't strip ".."
    with open(path, "r") as f:
        return f.read()

# ── Vulnerable: os.remove with user-controlled filename ──────────────────────
def delete_file():
    filename = input("File to delete: ")
    os.remove(UPLOAD_DIR + filename)              # attacker deletes any file on system

# ── Vulnerable: f-string path and open ───────────────────────────────────────
def preview_file():
    name = input("Preview which file? ")
    content = open(f"/var/app/public/{name}", "rb").read()  # traversal via f-string
    return content

# ── Vulnerable: download endpoint pattern (web-style) ────────────────────────
def download(request_args):
    filename = request_args.get("file")
    filepath = os.path.join("/downloads/", filename)
    return open(filepath, "rb").read()

# ── Safe alternatives (for comparison) ───────────────────────────────────────
from pathlib import Path

BASE = Path("/var/app/uploads").resolve()

def read_user_file_safe():
    filename = input("Enter filename: ")
    safe_name = os.path.basename(filename)        # strip any directory component
    target = (BASE / safe_name).resolve()

    if not str(target).startswith(str(BASE)):     # confirm still inside allowed dir
        raise ValueError("Access denied: path traversal detected.")

    return target.read_text()
