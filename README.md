# ThreatHunter SIEM

A Security Information and Event Management (SIEM) project built with Python and Flask. It brings my separate security tools together into one system that detects suspicious activity, enriches it with threat intelligence, and tracks investigations.

## Modules

| Module | Status | Based on |
|---|---|---|
| Log Analysis | ✅ Integrated | [log_parser_alerting_tool](https://github.com/Maliyka-L/log_parser_alerting_tool) |
| Alert Engine | ✅ Integrated | [alert_engine](https://github.com/Maliyka-L/alert_engine) |
| Threat Intelligence | ⬜ Planned | [Threat_Intelligence_module](https://github.com/Maliyka-L/Threat_Intelligence_module) |
| Case Management | ⬜ Planned | [Investigation_Manager](https://github.com/Maliyka-L/Investigation_Manager) |

## Log Analysis

Scans web server logs and raises alerts using six detection rules:

| Rule | What it detects | Severity |
|---|---|---|
| Brute force | Repeated failed logins (401/403) from one IP in a short time window | High |
| Admin access | Requests to `/admin` pages | Medium |
| After hours | Activity between 00:00 and 06:00 | Low |
| High volume | Too many requests from one IP in a short time | Medium |
| Endpoint scanning | One IP requesting many different pages | Medium |
| Suspicious user-agent | Tools such as curl, sqlmap, nmap and python-requests | Medium |

Thresholds, the allow list, severities and which rules are switched on are all set in `config/log_analysis.json`. Duplicate alerts for the same IP and rule are merged, keeping the strongest one.

## Alert Engine

Analyses host and authentication events (logins, process creation, account changes) and maps every detection to MITRE ATT&CK:

| Rule | What it detects | Severity | MITRE |
|---|---|---|---|
| Multiple failed logins | 5 or more failed logins from one IP | Medium | T1110 |
| Suspicious PowerShell | Encoded PowerShell commands | High | T1059 |
| New administrator account | An admin account being created | High | T1136 |
| Known malicious IP | An IP on the malicious IP list | Critical | T1071 |
| Possible account compromise | Failed logins, then a successful login from the same IP, then an admin account created within 60 minutes | Critical | T1078 |

Thresholds, the correlation window, the malicious IP list and which rules are switched on are set in `config/alert_engine.json`.

## How alerts come together

Both modules produce alerts in the same standard format, so the SIEM can show them side by side:

| Field | Meaning |
|---|---|
| `source` | Which module raised it (`log_analysis` or `alert_engine`) |
| `time` | When the activity happened |
| `ip` | The IP address involved, if any |
| `type` | The detection rule |
| `severity` | `low`, `medium`, `high` or `critical` |
| `reason` | What was detected |
| `mitre` | MITRE ATT&CK technique, where mapped |

Alert Engine alerts also carry extra details where relevant, such as the username, host or command.

The dashboard shows totals for each severity, and the alerts page lists every alert from both modules, most severe first.

## Running it locally

```bash
git clone https://github.com/Maliyka-L/ThreatHunter_SIEM.git
cd ThreatHunter_SIEM
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

By default the SIEM analyses `logs/web/sample.log` (web server logs) and `logs/host/sample_logs.json` (host events). To analyse different logs, set `SIEM_WEB_LOG` or `SIEM_HOST_LOG` before starting it:

```bash
$env:SIEM_WEB_LOG="logs/web/brute_force_activity.log"   # Windows PowerShell
$env:SIEM_HOST_LOG="logs/host/sample_logs.json"
# export SIEM_WEB_LOG=logs/web/brute_force_activity.log  # macOS / Linux
python app.py
```

To turn on Flask debug mode while developing, set `FLASK_DEBUG=1`. It's off by default.

## Log formats

**Web server logs** (one line per request): date, time, IP, method, path, status code and user-agent.

```
2024-10-05 10:01:01 192.168.0.10 GET /login 401 curl/7.88.1
```

**Host events** (a JSON list), for example:

```json
{"timestamp": "2026-11-01T08:15:00", "event_type": "failed_login", "source_ip": "10.0.0.5"}
```

## Project structure

```
ThreatHunter_SIEM/
├── app.py
├── requirements.txt
├── config/
│   ├── log_analysis.json      # web log rule settings
│   └── alert_engine.json      # host event rule settings
├── logs/
│   ├── web/                   # sample web server logs
│   └── host/                  # sample host events
├── modules/
│   ├── log_analysis.py        # web log detection
│   ├── alert_engine.py        # host event detection and correlation
│   ├── threat_intelligence.py
│   └── case_management.py
├── data/
└── templates/
    ├── dashboard.html
    └── alerts.html
```

## Licence

MIT
