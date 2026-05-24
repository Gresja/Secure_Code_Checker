"""
Sample: secure file I/O (reference implementation).

Purpose: with open() and try/except; expected 0 issues.
Contrasts with: samples/file_vulnerable.py
"""
def read_config(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except (FileNotFoundError, PermissionError) as e:
        print(f"Could not read config: {e}")
        return None


def write_log(log_file, message):
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(message + "\n")
