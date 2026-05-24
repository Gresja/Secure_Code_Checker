# Intentionally vulnerable — unsafe file handling patterns

# ── Vulnerable: open() without context manager or try/except ─────────────────
def read_config(path):
    f = open(path, "r")                  # file may never be closed on error
    data = f.read()
    f.close()
    return data

# ── Vulnerable: write without any error handling ──────────────────────────────
def save_report(filename, content):
    f = open(filename, "w")              # if write fails, file stays open and partial
    f.write(content)
    f.close()

# ── Vulnerable: open in append mode without context manager ──────────────────
def append_log(log_file, message):
    f = open(log_file, "a")             # unhandled IOError possible
    f.write(message + "\n")
    f.close()

# ── Vulnerable: binary open without try/except ────────────────────────────────
def read_binary(filepath):
    f = open(filepath, "rb")             # no resource cleanup on exception
    return f.read()

# ── Safe alternatives (for comparison) ───────────────────────────────────────
def read_config_safe(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except (FileNotFoundError, PermissionError) as e:
        print(f"Could not read config: {e}")
        return None

def save_report_safe(filename, content):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
