# Intentionally vulnerable - for testing only
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()    # weak!

def verify_file(data):
    return hashlib.sha1(data).hexdigest()                # weak!

def another_weak(data):
    return hashlib.new('md5', data).hexdigest()          # also weak!