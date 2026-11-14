import datetime
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "log_analysis.json")

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def load_config(path=CONFIG_PATH):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def parse_log_line(line):
    parts = line.strip().split()
    if len(parts) < 7:
        return None

    timestamp_str = f"{parts[0]} {parts[1]}"

    try:
        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "ip": parts[2],
        "method": parts[3],
        "path": parts[4],
        "status": parts[5],
        "user_agent": " ".join(parts[6:])
    }


def load_logs(path):
    events = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            parsed = parse_log_line(line)
            if parsed:
                events.append(parsed)

    return events


def make_alert(ip, time, reason, alert_type, config):
    return {
        "ip": ip,
        "time": time,
        "reason": reason,
        "type": alert_type,
        "severity": config["severity"][alert_type]
    }


def detect_bruteforce(events, config):
    if not config["rules"]["bruteforce"]:
        return []

    failed_codes = set(config["failed_status_codes"])
    allow_list = set(config["allow_list"])
    window = config["bruteforce_time_window"]
    threshold = config["max_failed_attempts"]

    suspicious = []
    events = sorted(events, key=lambda e: e["timestamp"])
    last_flagged_until = {}

    for i, event in enumerate(events):
        ip = event["ip"]

        if ip in allow_list or event["status"] not in failed_codes:
            continue

        window_start = event["timestamp"]

        if ip in last_flagged_until and window_start <= last_flagged_until[ip]:
            continue

        failed_count = 1

        for next_event in events[i + 1:]:
            if next_event["ip"] != ip:
                continue

            if (next_event["timestamp"] - window_start).total_seconds() > window:
                break

            if next_event["status"] in failed_codes:
                failed_count += 1

        if failed_count >= threshold:
            last_flagged_until[ip] = window_start + datetime.timedelta(seconds=window)
            suspicious.append(make_alert(
                ip, window_start,
                f"{failed_count} failed login attempts in {window}s",
                "bruteforce", config
            ))

    return suspicious


def detect_after_hours(events, config):
    if not config["rules"]["after_hours"]:
        return []

    allow_list = set(config["allow_list"])

    return [
        make_alert(event["ip"], event["timestamp"], "Activity outside normal hours", "after_hours", config)
        for event in events
        if event["ip"] not in allow_list and event["timestamp"].hour < 6
    ]


def detect_admin_access(events, config):
    if not config["rules"]["admin_access"]:
        return []

    allow_list = set(config["allow_list"])

    return [
        make_alert(event["ip"], event["timestamp"], "Accessed /admin page", "admin_access", config)
        for event in events
        if event["ip"] not in allow_list and event["path"].startswith("/admin")
    ]


def detect_high_volume(events, config):
    if not config["rules"]["high_volume"]:
        return []

    allow_list = set(config["allow_list"])
    window = config["high_volume_window"]
    threshold = config["high_volume_threshold"]

    suspicious = []
    events = sorted(events, key=lambda e: e["timestamp"])

    for i, event in enumerate(events):
        ip = event["ip"]

        if ip in allow_list:
            continue

        start_time = event["timestamp"]
        count = 1

        for next_event in events[i + 1:]:
            if next_event["ip"] != ip:
                continue

            if (next_event["timestamp"] - start_time).total_seconds() > window:
                break

            count += 1

        if count >= threshold:
            suspicious.append(make_alert(
                ip, start_time, f"{count} requests in {window}s", "high_volume", config
            ))

    return suspicious


def detect_endpoint_scanning(events, config):
    if not config["rules"]["endpoint_scan"]:
        return []

    allow_list = set(config["allow_list"])
    window = config["endpoint_scan_window"]
    threshold = config["endpoint_scan_threshold"]

    suspicious = []
    events = sorted(events, key=lambda e: e["timestamp"])

    for i, event in enumerate(events):
        ip = event["ip"]

        if ip in allow_list:
            continue

        start_time = event["timestamp"]
        paths_seen = {event["path"]}

        for next_event in events[i + 1:]:
            if next_event["ip"] != ip:
                continue

            if (next_event["timestamp"] - start_time).total_seconds() > window:
                break

            paths_seen.add(next_event["path"])

        if len(paths_seen) >= threshold:
            suspicious.append(make_alert(
                ip, start_time, f"{len(paths_seen)} unique endpoints scanned", "endpoint_scan", config
            ))

    return suspicious


def detect_suspicious_user_agents(events, config):
    if not config["rules"]["suspicious_user_agent"]:
        return []

    allow_list = set(config["allow_list"])
    bad_agents = [agent.lower() for agent in config["suspicious_user_agents"]]

    suspicious = []

    for event in events:
        if event["ip"] in allow_list:
            continue

        user_agent = event["user_agent"].lower()

        if any(bad in user_agent for bad in bad_agents):
            suspicious.append(make_alert(
                event["ip"], event["timestamp"],
                f"Suspicious user-agent: '{event['user_agent']}'",
                "suspicious_user_agent", config
            ))

    return suspicious


def dedupe_alerts(alerts):
    strongest = {}

    for alert in alerts:
        key = (alert["ip"], alert["type"])

        if key not in strongest:
            strongest[key] = alert
            continue

        if alert["type"] in ("bruteforce", "high_volume", "endpoint_scan"):
            if int(alert["reason"].split()[0]) > int(strongest[key]["reason"].split()[0]):
                strongest[key] = alert

    return list(strongest.values())


def run_detection(log_path, config=None):
    config = config or load_config()

    if not os.path.isabs(log_path):
        log_path = os.path.join(BASE_DIR, log_path)

    if not os.path.exists(log_path):
        return []

    events = load_logs(log_path)

    alerts = []
    alerts += detect_bruteforce(events, config)
    alerts += detect_admin_access(events, config)
    alerts += detect_after_hours(events, config)
    alerts += detect_high_volume(events, config)
    alerts += detect_endpoint_scanning(events, config)
    alerts += detect_suspicious_user_agents(events, config)

    alerts = dedupe_alerts(alerts)
    alerts.sort(key=lambda a: (-SEVERITY_ORDER.get(a["severity"], 0), a["time"]))

    return [
        {
            "source": "log_analysis",
            "ip": alert["ip"],
            "time": alert["time"].strftime("%Y-%m-%d %H:%M:%S"),
            "type": alert["type"],
            "severity": alert["severity"],
            "reason": alert["reason"]
        }
        for alert in alerts
    ]
