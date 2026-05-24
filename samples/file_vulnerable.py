"""
Sample: unsafe file handling (for testing only).

Purpose: Demonstrate UNSAFE_FILE_HANDLING (open without with/try).
Expected: MEDIUM findings.
Pair with: samples/safe/file_safe.py (0 issues).
"""
def read_config():
    f = open("config.txt", "r")
    data = f.read()
    f.close()
    return data

def write_log(message):
    f = open("log.txt", "w")
    f.write(message)
    f.close()
