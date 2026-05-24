"""
Sample: secrets in config (for testing only).

Purpose: Demonstrate HARDCODED_CREDENTIAL in variables, dicts, and class attrs.
Expected: Multiple CRITICAL findings.
Pair with: samples/safe/credentials_safe.py (0 issues).
"""
# ── Vulnerable: credentials hardcoded at module level ────────────────────────
API_KEY        = "sk-proj-abc123xyz456def789"
token          = "ghp_RealTokenExample1234567890abcdef"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
db_password    = "Passw0rd!prod"
private_key    = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."

# ── Vulnerable: credentials in a config dictionary ───────────────────────────
DATABASE_CONFIG = {
    "host":     "db.internal",
    "port":     5432,
    "username": "admin",
    "password": "pg_super_secret",       # hardcoded in dict
    "api_key":  "key-prod-9999xyzabc",   # hardcoded in dict
}

# ── Vulnerable: class attribute holding a secret ─────────────────────────────
class SMTPClient:
    def __init__(self):
        self.password = "smtp_pass_2024"  # credential in attribute

    def connect(self):
        import smtplib
        server = smtplib.SMTP("mail.example.com", 587)
        server.login("user@example.com", self.password)
        return server

# ── Safe alternative (for comparison) ────────────────────────────────────────
import os

def get_api_key_safe():
    return os.environ.get("API_KEY")     # loaded from environment, not hardcoded
