import json
import os
import re
from datetime import datetime

import requests

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "case_management.json")
CASES_PATH = os.path.join(BASE_DIR, "data", "cases.json")

if load_dotenv:
    load_dotenv(os.path.join(BASE_DIR, ".env"))

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
MITRE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")
SEVERITY_NAMES = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}


def load_config(path=CONFIG_PATH):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def get_settings():
    url = (os.getenv("IM_URL") or "http://127.0.0.1:5000").strip().strip('"').strip("'").rstrip("/")
    key = (os.getenv("IM_API_KEY") or "").strip().strip('"').strip("'")
    return url, key


def load_cases(path=CASES_PATH):
    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

    return data if isinstance(data, dict) else {}


def save_cases(cases, path=CASES_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(cases, file, indent=4)


def alert_key(alert):
    target = alert.get("ip") or alert.get("host") or alert.get("username") or "-"
    return "|".join([alert.get("source", ""), alert.get("type", ""), target, alert.get("time", "")])


def parse_mitre(value):
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)

    found = MITRE_PATTERN.findall(str(value or "").upper())
    return list(dict.fromkeys(found))


def build_payload(alert, config):
    target = alert.get("ip") or alert.get("host") or alert.get("username") or "unknown"
    rule = alert.get("title") or alert.get("type", "alert").replace("_", " ").title()
    title = f"{rule} - {target}"[:200]

    lines = [
        f"Raised by: {alert.get('source', 'unknown')}",
        f"Time: {alert.get('time', 'unknown')}",
        f"Reason: {alert.get('reason', '')}",
    ]

    for field, label in (("ip", "IP"), ("host", "Host"), ("username", "Username"), ("command", "Command")):
        if alert.get(field):
            lines.append(f"{label}: {alert[field]}")

    intel = alert.get("threat_intel") or {}
    if intel.get("status") == "checked":
        lines.append(f"Threat intel: {intel.get('severity')} (risk score {intel.get('risk_score')}/100)")

    payload = {
        "title": title,
        "severity": SEVERITY_NAMES.get(alert.get("severity"), "Medium"),
        "source": config.get("case_source", "ThreatHunter SIEM"),
        "description": "\n".join(lines)[:5000],
        "iocs": [],
        "mitre": parse_mitre(alert.get("mitre"))
    }

    if alert.get("ip"):
        payload["iocs"].append({"type": "IP", "value": alert["ip"]})

    return payload


def explain_error(response):
    if response.status_code == 401:
        return "Investigation Manager rejected the API key (check IM_API_KEY matches in both projects)"
    if response.status_code == 503:
        return "Investigation Manager's API is switched off (IM_API_KEY isn't set where it's running)"
    if response.status_code == 400:
        return "Investigation Manager rejected the case data"
    return f"Investigation Manager returned an error ({response.status_code})"


def eligible_alerts(alerts, config=None):
    config = config or load_config()
    levels = set(config["create_for_severities"])
    return [a for a in alerts if a.get("severity") in levels]


def create_cases(alerts, config=None, cases_path=CASES_PATH):
    config = config or load_config()
    url, key = get_settings()
    cases = load_cases(cases_path)

    summary = {"created": 0, "already_open": 0, "error": ""}

    if not key:
        summary["error"] = "IM_API_KEY is not set in .env"
        return summary

    for alert in eligible_alerts(alerts, config):
        k = alert_key(alert)

        if k in cases:
            summary["already_open"] += 1
            continue

        payload = build_payload(alert, config)

        try:
            response = requests.post(
                f"{url}/api/cases",
                json=payload,
                headers={"X-API-Key": key},
                timeout=config.get("request_timeout", 10)
            )
        except requests.RequestException:
            summary["error"] = f"Could not reach Investigation Manager at {url} (is it running?)"
            break

        if response.status_code != 201:
            summary["error"] = explain_error(response)
            if response.status_code in (401, 503):
                break
            continue

        try:
            case_id = response.json().get("case_id")
        except ValueError:
            case_id = None

        if not case_id:
            summary["error"] = "Investigation Manager sent back an unexpected reply"
            continue

        cases[k] = {
            "case_id": case_id,
            "title": payload["title"],
            "severity": payload["severity"],
            "alert_source": alert.get("source", ""),
            "alert_type": alert.get("type", ""),
            "alert_time": alert.get("time", ""),
            "created": datetime.now().strftime(TIME_FORMAT)
        }
        summary["created"] += 1

    save_cases(cases, cases_path)
    return summary


def attach_cases(alerts, cases_path=CASES_PATH):
    cases = load_cases(cases_path)

    for alert in alerts:
        case = cases.get(alert_key(alert))
        alert["case_id"] = case["case_id"] if case else None

    return alerts
