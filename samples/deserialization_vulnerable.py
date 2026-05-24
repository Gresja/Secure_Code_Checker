# Intentionally vulnerable — insecure deserialization examples

import pickle
import yaml

# ── Vulnerable: pickle.loads on untrusted bytes ───────────────────────────────
def load_user_session(session_bytes):
    user = pickle.loads(session_bytes)       # attacker can craft bytes that run code
    return user

# ── Vulnerable: pickle.load from a file path given by user ───────────────────
def restore_object(filepath):
    with open(filepath, "rb") as f:
        obj = pickle.load(f)                 # if file is attacker-supplied, RCE possible
    return obj

# ── Vulnerable: yaml.load without SafeLoader ──────────────────────────────────
def parse_config(config_str):
    config = yaml.load(config_str)           # can instantiate arbitrary Python objects
    return config

# ── Vulnerable: yaml.load with explicit None Loader ───────────────────────────
def parse_config_explicit(config_str):
    config = yaml.load(config_str, Loader=None)   # None loader is also unsafe
    return config

# ── Vulnerable: yaml.load from file ───────────────────────────────────────────
def load_settings(path):
    with open(path, "r") as f:
        settings = yaml.load(f)              # same problem from a file source
    return settings

# ── Safe alternatives (for comparison) ───────────────────────────────────────
import json

def load_user_session_safe(session_json):
    return json.loads(session_json)          # JSON cannot execute code

def parse_config_safe(config_str):
    return yaml.safe_load(config_str)        # SafeLoader only allows simple types
