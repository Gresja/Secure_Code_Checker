# Safe example — subprocess without shell; fixed argument lists

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
