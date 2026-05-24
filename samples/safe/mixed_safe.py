# Safe example — multiple secure patterns combined (should produce zero findings)

import json
import os
import secrets
import sqlite3
import hashlib
from pathlib import Path

BASE_DIR = Path("/var/app/data").resolve()


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def load_config():
    api_key = os.environ.get("API_KEY")
    with open("config.json", "r", encoding="utf-8") as f:
        return json.load(f), api_key


def create_session():
    return secrets.token_hex(32)


def read_allowed_file(name):
    safe_name = os.path.basename(name)
    path = (BASE_DIR / safe_name).resolve()
    if not str(path).startswith(str(BASE_DIR)):
        raise ValueError("Invalid path")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def checksum(data: bytes):
    return hashlib.sha256(data).hexdigest()
