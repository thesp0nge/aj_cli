import json
import os

CONFIG_PATH = os.path.expanduser("~/.aj_config")


def get_config():
    """Carica la configurazione o crea un template se non esiste."""
    if not os.path.exists(CONFIG_PATH):
        default_config = {
            "bugzilla_api_key": "",
            "bugzilla_url": "https://bugzilla.suse.com",
            "default_report_format": "markdown",
        }
        with open(CONFIG_PATH, "w") as f:
            json.dump(default_config, f, indent=4)
        print(f"[*] Config file created at {CONFIG_PATH}")
        return default_config

    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


def save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)
