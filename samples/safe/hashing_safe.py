"""
Sample: secure hashing (reference implementation).

Purpose: bcrypt for passwords, SHA-256 for checksums; expected 0 issues.
Contrasts with: samples/hashing_vulnerable.py
"""
import hashlib
import bcrypt


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)


def file_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
