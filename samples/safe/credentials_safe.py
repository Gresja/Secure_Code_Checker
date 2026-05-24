# Safe example — secrets loaded from environment, not hardcoded

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
