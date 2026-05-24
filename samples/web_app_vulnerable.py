"""
Sample: insecure web-app style code (for testing only).

Purpose: SQL injection, credentials, weak hash, eval in one file.
Expected: Multiple rule types triggered.
Pair with: samples/safe/mixed_safe.py or individual safe samples.
"""
import hashlib
import sqlite3

SECRET_KEY = "supersecretkey123"          # hardcoded secret
DB_PASSWORD = "root"                      # hardcoded DB password

# ── Vulnerable: SQL injection via string concatenation ────────────────────────
def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

# ── Vulnerable: SQL injection via f-string ────────────────────────────────────
def get_order(order_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    return cursor.fetchone()

# ── Vulnerable: password stored with weak hash ────────────────────────────────
def store_password(raw_password):
    hashed = hashlib.md5(raw_password.encode()).hexdigest()
    return hashed

# ── Vulnerable: login check using MD5 ────────────────────────────────────────
def verify_login(username, raw_password):
    hashed = hashlib.sha1(raw_password.encode()).hexdigest()
    stored = get_user(username)
    return stored and stored[2] == hashed

# ── Vulnerable: eval on user input ────────────────────────────────────────────
def calculate(expression):
    return eval(expression)               # user could pass __import__('os').system('...')
