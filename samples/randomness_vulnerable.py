# Intentionally vulnerable — insecure randomness for security-sensitive values

import random

# ── Vulnerable: random used to generate a session ID ─────────────────────────
def create_session():
    session_id = random.randint(100000, 999999)   # predictable 6-digit number
    return str(session_id)

# ── Vulnerable: random used to generate a password reset token ───────────────
def generate_reset_token():
    token = random.getrandbits(64)                # Mersenne Twister — not secure
    return hex(token)

# ── Vulnerable: random used to build an API key ──────────────────────────────
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"

def generate_api_key():
    api_key = "".join(random.choice(CHARSET) for _ in range(32))  # predictable
    return api_key

# ── Vulnerable: random used to generate a one-time PIN ───────────────────────
def generate_otp():
    pin = random.randrange(1000, 9999)            # trivially brute-forceable
    return pin

# ── Vulnerable: random used as a salt for hashing ────────────────────────────
def make_salt():
    salt = random.getrandbits(128)                # salt must be unpredictable
    return salt.to_bytes(16, "big")

# ── Safe alternatives (for comparison) ───────────────────────────────────────
import secrets

def create_session_safe():
    return secrets.token_hex(32)                  # 256 bits of secure randomness

def generate_reset_token_safe():
    return secrets.token_urlsafe(32)              # URL-safe, cryptographically secure

def generate_api_key_safe():
    return secrets.token_hex(24)                  # 48-char hex key

def generate_otp_safe():
    return secrets.randbelow(9000) + 1000         # secure 4-digit OTP
