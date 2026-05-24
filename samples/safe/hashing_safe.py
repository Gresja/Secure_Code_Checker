# Safe example — strong hashing for integrity; bcrypt for passwords

import hashlib
import bcrypt


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)


def file_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
