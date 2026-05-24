"""
Sample: command injection (for testing only).

Purpose: Demonstrate COMMAND_INJECTION_RISK (os.system, shell=True).
Expected: CRITICAL findings.
Pair with: samples/safe/command_injection_safe.py (0 issues).
"""
import os
import subprocess

# ── Vulnerable: os.system with user-controlled input ──────────────────────────
def delete_user_file(filename):
    os.system("rm /uploads/" + filename)         # attacker passes "x; rm -rf /"

# ── Vulnerable: os.popen builds a shell command from input ────────────────────
def get_disk_usage(path):
    result = os.popen("du -sh " + path)          # path could be "/ && cat /etc/passwd"
    return result.read()

# ── Vulnerable: subprocess.run with shell=True and user input ─────────────────
def ping_host(hostname):
    output = subprocess.run(
        "ping -c 1 " + hostname,
        shell=True,
        capture_output=True
    )
    return output.stdout

# ── Vulnerable: subprocess.Popen with shell=True ──────────────────────────────
def run_report(report_name):
    proc = subprocess.Popen(
        f"python reports/{report_name}.py",
        shell=True,
        stdout=subprocess.PIPE
    )
    return proc.communicate()

# ── Safe alternatives (for comparison) ───────────────────────────────────────
def safe_ping(hostname):
    # Pass arguments as a list — no shell interpretation
    output = subprocess.run(
        ["ping", "-c", "1", hostname],
        capture_output=True,
        check=True
    )
    return output.stdout
