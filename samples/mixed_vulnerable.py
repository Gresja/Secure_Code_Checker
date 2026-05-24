"""
Sample: combined vulnerabilities (for testing only).

Purpose: Demo many rules in one script (SQL, secrets, hash, eval, command, files).
Expected: High issue count and CRITICAL risk level.
Pair with: samples/safe/mixed_safe.py (0 issues).
"""
import os
import hashlib
import sqlite3
import subprocess

# ── Hardcoded credentials ─────────────────────────────────────────────────────
DB_PASSWORD = "admin123"
api_key     = "sk-live-abc123xyz"

# ── Insecure DB query ─────────────────────────────────────────────────────────
def find_product(name):
    conn   = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    query  = "SELECT * FROM products WHERE name = '" + name + "'"
    cursor.execute(query)
    return cursor.fetchall()

# ── Weak hashing for integrity check ──────────────────────────────────────────
def file_checksum(filepath):
    data = open(filepath, "rb").read()   # also unsafe file open
    return hashlib.md5(data).hexdigest()

# ── Unsafe password storage ───────────────────────────────────────────────────
def register_user(username, password):
    hashed = hashlib.sha1(password.encode()).hexdigest()
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    query = "INSERT INTO users VALUES ('" + username + "', '" + hashed + "')"
    cursor.execute(query)
    conn.commit()

# ── Command injection via user-supplied filename ──────────────────────────────
def compress_file(filename):
    os.system("zip output.zip " + filename)   # filename could be "x; cat /etc/passwd"

# ── Dangerous eval ────────────────────────────────────────────────────────────
def apply_discount(rule):
    multiplier = eval(rule)                   # caller passes Python expression
    return multiplier

# ── Shell subprocess on user input ───────────────────────────────────────────
def send_notification(email):
    subprocess.run(f"mail -s 'Alert' {email}", shell=True)
