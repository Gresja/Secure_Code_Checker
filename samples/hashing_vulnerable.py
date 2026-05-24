"""
Sample: weak hashing (for testing only).

Purpose: Demonstrate WEAK_HASHING_ALGORITHM (MD5, SHA1, hashlib.new).
Expected: HIGH findings on lines using md5/sha1.
Pair with: samples/safe/hashing_safe.py (0 issues).
"""
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()    # weak!

def verify_file(data):
    return hashlib.sha1(data).hexdigest()                # weak!

def another_weak(data):
    return hashlib.new('md5', data).hexdigest()          # also weak!