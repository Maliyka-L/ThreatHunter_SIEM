import json
import os
from collections import Counter
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "alert_engine.json")

MITRE_MAPPINGS = {
    "Multiple Failed Logins": "T1110",
    "Suspicious PowerShell Activity": "T1059",
    "New Administrator Account": "T1136",
    "Known Malicious IP": "T1071",
    "Possible Account Compromise": "T1078"
}

ALERT_TYPES = {
    "Multiple Failed Logins": "failed_logins",
    "Suspicious PowerShell Activity": "suspicious_powershell",
    "New Administrator Account": "admin_creation",
    "Known Malicious IP": "known_malicious_ip",
    "Possible Account Compromise": "account_compromise"
}


def load_config(path=CONFIG_PATH):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_logs(path):
    with open(path, "r", encoding="utf-8") as file:
        logs = json.load(file)

    return [log for log in logs if isinstance(log, dict)] if isinstance(logs, list) else []


def calculate_severity(score):
    if score >= 20:
        return "CRITICAL"

    if score >= 10:
        return "HIGH"

    if score >= 5:
        return "MEDIUM"

    return "LOW"


def get_mitre(alert_title):
    return MITRE_MAPPINGS.get(alert_title, "Unknown")


def parse_timestamp(log):
    try:
        return datetime.fromisoformat(log.get("timestamp", ""))
    except (TypeError, ValueError):
        return None


def build_alert(title, score, description, timestamp=None, **details):
    alert = {
        "title": title,
        "score": score,
        "severity": calculate_severity(score),
        "mitre": get_mitre(title),
        "description": description,
        "timestamp": timestamp
    }
    alert.update({key: value for key, value in details.items() if value is not None})
    return alert


def detect_failed_logins(logs, config):
    if not config["rules"]["failed_logins"]:
        return []

    threshold = config["failed_login_threshold"]
    counts = Counter()
    first_seen = {}

    for log in logs:
        if log.get("event_type") == "failed_login":
            ip = log.get("source_ip")
            counts[ip] += 1
            first_seen.setdefault(ip, log.get("timestamp"))

    return [
        build_alert(
            "Multiple Failed Logins", 5,
            f"{count} failed login attempts detected.",
            first_seen[ip], source_ip=ip
        )
        for ip, count in counts.items()
        if count >= threshold
    ]


def detect_suspicious_powershell(logs, config):
    if not config["rules"]["suspicious_powershell"]:
        return []

    alerts = []

    for log in logs:
        command = log.get("command", "").lower()

        if "powershell" in command and "encodedcommand" in command:
            alerts.append(build_alert(
                "Suspicious PowerShell Activity", 10,
                "Encoded PowerShell command detected.",
                log.get("timestamp"),
                command=log.get("command"),
                host=log.get("hostname") or log.get("host")
            ))

    return alerts


def detect_admin_creation(logs, config):
    if not config["rules"]["admin_creation"]:
        return []

    return [
        build_alert(
            "New Administrator Account", 15,
            "Administrator account created.",
            log.get("timestamp"),
            username=log.get("username"),
            host=log.get("hostname") or log.get("host")
        )
        for log in logs
        if log.get("event_type") == "admin_created"
    ]


def detect_ioc_match(logs, config):
    if not config["rules"]["ioc_match"]:
        return []

    malicious_ips = set(config["malicious_ips"])

    return [
        build_alert(
            "Known Malicious IP", 20,
            "IP matched threat intelligence feed.",
            log.get("timestamp"),
            source_ip=log.get("source_ip")
        )
        for log in logs
        if log.get("source_ip") in malicious_ips
    ]


def detect_account_compromise(logs, config):
    if not config["rules"]["account_compromise"]:
        return []

    min_failed = config["correlation_min_failed"]
    window_minutes = config["correlation_window_minutes"]

    events = []

    for log in logs:
        timestamp = parse_timestamp(log)
        if timestamp is not None:
            events.append((timestamp, log))

    events.sort(key=lambda item: item[0])

    alerts = []
    failed_counts = Counter()

    for index, (timestamp, log) in enumerate(events):
        event_type = log.get("event_type")
        ip = log.get("source_ip")

        if event_type == "failed_login" and ip:
            failed_counts[ip] += 1
            continue

        if event_type != "successful_login" or failed_counts[ip] < min_failed:
            continue

        deadline = timestamp + timedelta(minutes=window_minutes)

        for later_time, later_log in events[index + 1:]:
            if later_time > deadline:
                break

            if later_log.get("event_type") == "admin_created":
                alerts.append(build_alert(
                    "Possible Account Compromise", 25,
                    f"{failed_counts[ip]} failed logins from {ip}, "
                    f"followed by a successful login and "
                    f"administrator account creation within "
                    f"{window_minutes} minutes.",
                    later_log.get("timestamp"),
                    source_ip=ip,
                    username=later_log.get("username")
                ))
                break

        failed_counts[ip] = 0

    return alerts


def format_time(value):
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return ""


def run_detection(log_path, config=None):
    config = config or load_config()

    if not os.path.isabs(log_path):
        log_path = os.path.join(BASE_DIR, log_path)

    if not os.path.exists(log_path):
        return []

    try:
        logs = load_logs(log_path)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    alerts = []
    alerts += detect_failed_logins(logs, config)
    alerts += detect_suspicious_powershell(logs, config)
    alerts += detect_admin_creation(logs, config)
    alerts += detect_ioc_match(logs, config)
    alerts += detect_account_compromise(logs, config)

    return [
        {
            "source": "alert_engine",
            "ip": alert.get("source_ip", ""),
            "time": format_time(alert.get("timestamp")),
            "type": ALERT_TYPES[alert["title"]],
            "severity": alert["severity"].lower(),
            "reason": alert["description"],
            "title": alert["title"],
            "mitre": alert["mitre"],
            "score": alert["score"],
            "username": alert.get("username", ""),
            "host": alert.get("host", ""),
            "command": alert.get("command", "")
        }
        for alert in alerts
    ]
