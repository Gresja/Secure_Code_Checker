"""
Sample: secure credential handling (reference implementation).

Purpose: Secrets from os.environ only; expected 0 issues.
Contrasts with: samples/credentials_vulnerable.py
"""
import os


def connect():
    password = os.environ.get("DB_PASSWORD")
    api_key = os.environ.get("API_KEY")
    token = os.environ.get("AUTH_TOKEN")
    return password, api_key, token


def get_db_config():
    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "user": os.environ.get("DB_USER"),
        "password": os.environ.get("DB_PASSWORD"),
    }
