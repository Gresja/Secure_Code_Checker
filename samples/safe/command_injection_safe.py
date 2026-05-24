"""
Sample: safe subprocess usage (reference implementation).

Purpose: Argument lists, no shell=True; expected 0 issues.
Contrasts with: samples/command_injection_vulnerable.py
"""
import subprocess


def ping_host(hostname):
    return subprocess.run(
        ["ping", "-c", "1", hostname],
        capture_output=True,
        check=True,
        text=True,
    )


def list_directory(directory):
    return subprocess.run(
        ["ls", "-la", directory],
        capture_output=True,
        check=True,
        text=True,
    )
