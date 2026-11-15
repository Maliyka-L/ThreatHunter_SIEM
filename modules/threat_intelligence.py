import ipaddress
import json
import os
import re
from datetime import datetime, timedelta

import requests

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "threat_intelligence.json")
CACHE_PATH = os.path.join(BASE_DIR, "data", "indicators.json")

if load_dotenv:
    load_dotenv(os.path.join(BASE_DIR, ".env"))

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def load_config(path=CONFIG_PATH):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def get_keys():
    vt_key = (os.getenv("VT_API_KEY") or "").strip().strip('"').strip("'")
    abuse_key = (os.getenv("ABUSEIPDB_API_KEY") or "").strip().strip('"').strip("'")
    return vt_key, abuse_key


def detect_ioc_type(ioc):
    ioc = (ioc or "").strip()

    try:
        ip = ipaddress.ip_address(ioc)

        if ip.version == 4:
            if not ip.is_global:
                return "Private IPv4"
            return "IPv4"

    except ValueError:
        pass

    patterns = {
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA1": r"^[a-fA-F0-9]{40}$",
        "SHA256": r"^[a-fA-F0-9]{64}$",
        "URL": r"^https?://",
        "Domain": r"^(?!:\/\/)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    }

    for ioc_type, pattern in patterns.items():
        if re.match(pattern, ioc):
            return ioc_type

    return "Unknown"


def check_virustotal_ip(ip, api_key, timeout=15):
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=timeout
        )

        if response.status_code == 200:
            attributes = response.json()["data"]["attributes"]
            stats = attributes["last_analysis_stats"]

            return {
                "reputation": attributes.get("reputation", 0),
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "harmless": stats["harmless"]
            }

        return {"error": f"API Error: {response.status_code}"}

    except Exception as error:
        return {"error": str(error)}


def check_abuseipdb(ip, api_key, timeout=15):
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=timeout
        )

        if response.status_code == 200:
            data = response.json()["data"]

            return {
                "abuse_score": data["abuseConfidenceScore"],
                "country": data["countryCode"],
                "reports": data["totalReports"]
            }

        return {"error": f"API Error {response.status_code}"}

    except Exception as error:
        return {"error": str(error)}


def calculate_risk_score(vt_result, abuse_result):
    score = 0

    if vt_result and "error" not in vt_result:
        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)
        reputation = vt_result.get("reputation", 0)

        if malicious >= 10:
            score += 40
        elif malicious >= 5:
            score += 30
        elif malicious >= 3:
            score += 15
        elif malicious >= 1:
            score += 5

        if suspicious >= 3:
            score += 10

        if reputation < 0:
            score += 10
        elif reputation > 100:
            score -= 10

    if abuse_result and "error" not in abuse_result:
        abuse_score = abuse_result.get("abuse_score", 0)
        reports = abuse_result.get("reports", 0)

        if abuse_score >= 75:
            score += 40
        elif abuse_score >= 50:
            score += 25
        elif abuse_score >= 25:
            score += 10

        if reports >= 100 and abuse_score >= 25:
            score += 20

    score = max(0, min(score, 100))

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {"risk_score": score, "severity": severity}


def map_to_mitre(vt_result, abuse_result, risk_result):
    techniques = []

    if risk_result["severity"] == "LOW":
        return techniques

    if not vt_result or "error" in vt_result:
        vt_result = {}

    if not abuse_result or "error" in abuse_result:
        abuse_result = {}

    if vt_result.get("malicious", 0) >= 1:
        techniques.append({"id": "T1071", "name": "Application Layer Protocol"})

    if abuse_result.get("abuse_score", 0) >= 50:
        techniques.append({"id": "T1110", "name": "Brute Force"})

    if abuse_result.get("reports", 0) >= 100:
        techniques.append({"id": "T1595", "name": "Active Scanning"})

    return techniques


def load_cache(path=CACHE_PATH):
    try:
        with open(path, "r", encoding="utf-8") as file:
            cache = json.load(file)
        return cache if isinstance(cache, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def save_cache(cache, path=CACHE_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(cache, file, indent=4)


def is_fresh(entry, cache_hours):
    try:
        checked = datetime.strptime(entry["checked"], TIME_FORMAT)
    except (KeyError, TypeError, ValueError):
        return False

    return datetime.now() - checked < timedelta(hours=cache_hours)


def lookup_ip(ip, vt_key, abuse_key, timeout):
    vt_result = check_virustotal_ip(ip, vt_key, timeout) if vt_key else {"error": "No VirusTotal key"}
    abuse_result = check_abuseipdb(ip, abuse_key, timeout) if abuse_key else {"error": "No AbuseIPDB key"}

    if "error" in vt_result and "error" in abuse_result:
        return {
            "status": "error",
            "error": f"VirusTotal: {vt_result['error']} | AbuseIPDB: {abuse_result['error']}"
        }

    risk_result = calculate_risk_score(vt_result, abuse_result)

    return {
        "status": "checked",
        "checked": datetime.now().strftime(TIME_FORMAT),
        "virustotal": vt_result,
        "abuseipdb": abuse_result,
        "risk_score": risk_result["risk_score"],
        "severity": risk_result["severity"],
        "mitre": map_to_mitre(vt_result, abuse_result, risk_result)
    }


def enrich_ips(ips, config=None, cache_path=CACHE_PATH):
    config = config or load_config()
    vt_key, abuse_key = get_keys()
    keys_configured = bool(vt_key or abuse_key)

    cache = load_cache(cache_path)
    results = {}
    lookups = 0
    cache_changed = False

    for ip in sorted(set(ip for ip in ips if ip)):
        ioc_type = detect_ioc_type(ip)

        if ioc_type == "Private IPv4":
            results[ip] = {"status": "private"}
            continue

        if ioc_type != "IPv4":
            results[ip] = {"status": "unsupported"}
            continue

        cached = cache.get(ip)

        if cached and is_fresh(cached, config["cache_hours"]):
            results[ip] = cached
            continue

        if not keys_configured:
            results[ip] = {"status": "not_configured"}
            continue

        if lookups >= config["max_lookups_per_run"]:
            results[ip] = cached or {"status": "pending"}
            continue

        lookups += 1
        result = lookup_ip(ip, vt_key, abuse_key, config["request_timeout"])
        results[ip] = result

        if result["status"] == "checked":
            cache[ip] = result
            cache_changed = True

    if cache_changed:
        save_cache(cache, cache_path)

    return results


def enrich_alerts(alerts, config=None, cache_path=CACHE_PATH):
    config = config or load_config()
    intel = enrich_ips([alert.get("ip") for alert in alerts], config, cache_path)

    for alert in alerts:
        alert["threat_intel"] = intel.get(alert.get("ip"), {"status": "none"})

    alert_levels = set(config["alert_on_severities"])
    new_alerts = []

    for ip, result in intel.items():
        if result.get("status") == "checked" and result.get("severity") in alert_levels:
            times = [a.get("time", "") for a in alerts if a.get("ip") == ip and a.get("time")]
            mitre = result.get("mitre") or []

            new_alerts.append({
                "source": "threat_intelligence",
                "ip": ip,
                "time": min(times) if times else result.get("checked", ""),
                "type": "malicious_ip",
                "severity": "critical",
                "reason": (
                    f"Threat intelligence rates this IP {result['severity']} "
                    f"(risk score {result['risk_score']}/100)."
                ),
                "mitre": ", ".join(t["id"] for t in mitre) or "",
                "threat_intel": result
            })

    return alerts + new_alerts, intel
