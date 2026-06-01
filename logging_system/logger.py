import json
import os
from datetime import datetime

LOG_FILE = "logs/idps.jsonl"

# Ensure logs folder exists
os.makedirs("logs", exist_ok=True)


def log_event(data: dict):
    """
    Append a log entry as JSON line
    """
    try:
        entry = {"timestamp": datetime.utcnow().isoformat() + "Z", **data}

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    except Exception as e:
        print(f"[Logger] Failed to write log: {e}")


def read_logs(limit: int = 100):
    import os, json

    LOG_FILE = "logs/idps.jsonl"

    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    logs = [json.loads(line) for line in lines[-limit:]]
    return logs[::-1]
