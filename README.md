# ThreatHunter SIEM

A Security Information and Event Management (SIEM) project built with Python and Flask. It brings my separate security tools together into one system that detects suspicious activity, enriches it with threat intelligence, and tracks investigations.

## Modules

| Module | Status | Based on |
|---|---|---|
| Log Analysis | ✅ Integrated | [log_parser_alerting_tool](https://github.com/Maliyka-L/log_parser_alerting_tool) |
| Alert Engine | ⬜ Planned | [alert_engine](https://github.com/Maliyka-L/alert_engine) |
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

The SIEM dashboard shows alert totals by severity, and the alerts page lists every alert with its time, IP, type, severity and reason.

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

By default the SIEM analyses `logs/web/sample.log`. To analyse a different log, set `SIEM_WEB_LOG` before starting it:

```bash
$env:SIEM_WEB_LOG="logs/web/brute_force_activity.log"   # Windows PowerShell
# export SIEM_WEB_LOG=logs/web/brute_force_activity.log  # macOS / Linux
python app.py
```

To turn on Flask debug mode while developing, set `FLASK_DEBUG=1`. It's off by default.

## Log format

Each line is: date, time, IP, method, path, status code and user-agent.

```
2024-10-05 10:01:01 192.168.0.10 GET /login 401 curl/7.88.1
```

## Project structure

```
ThreatHunter_SIEM/
├── app.py
├── requirements.txt
├── config/
│   └── log_analysis.json      # detection rule settings
├── logs/
│   └── web/                   # sample web server logs
├── modules/
│   ├── log_analysis.py        # web log detection
│   ├── alert_engine.py
│   ├── threat_intelligence.py
│   └── case_management.py
├── data/
└── templates/
    ├── dashboard.html
    └── alerts.html
```

## Licence

MIT
