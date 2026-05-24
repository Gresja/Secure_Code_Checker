"""
Sample: hardcoded credentials (for testing only).

Purpose: Demonstrate HARDCODED_CREDENTIAL detections.
Expected: CRITICAL findings on password, api_key, token, etc.
Pair with: samples/safe/credentials_safe.py (0 issues).
"""
password = "admin1234"
api_key = "sk-abc123xyz789"
secret = "mysecretkey"
db_password = "root123"

def connect():
    token = "Bearer eyJhbGciOiJIUzI1NiJ9"
    return token
