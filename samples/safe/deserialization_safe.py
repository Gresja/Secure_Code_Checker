# Safe example — JSON and yaml.safe_load only

import json
import yaml


def load_user_session(session_json: str):
    return json.loads(session_json)


def parse_config(config_str: str):
    return yaml.safe_load(config_str)


def load_settings_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
