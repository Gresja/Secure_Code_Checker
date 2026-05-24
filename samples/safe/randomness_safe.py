"""
Sample: cryptographically secure randomness (reference implementation).

Purpose: secrets module for tokens/IDs; expected 0 issues.
Contrasts with: samples/randomness_vulnerable.py
"""
import secrets


def create_session_id():
    return secrets.token_hex(32)


def generate_reset_token():
    return secrets.token_urlsafe(32)


def generate_api_key():
    return secrets.token_hex(24)


def generate_otp():
    return secrets.randbelow(9000) + 1000
