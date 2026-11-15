# ThreatHunter SIEM

A Security Information and Event Management (SIEM) project built with Python and Flask. It brings my separate security tools together into one system that detects suspicious activity, enriches it with threat intelligence, and tracks investigations.

## Modules

| Module | Status | Based on |
|---|---|---|
| Log Analysis | ✅ Integrated | [log_parser_alerting_tool](https://github.com/Maliyka-L/log_parser_alerting_tool) |
| Alert Engine | ✅ Integrated | [alert_engine](https://github.com/Maliyka-L/alert_engine) |
| Threat Intelligence | ✅ Integrated | [Threat_Intelligence_module](https://github.com/Maliyka-L/Threat_Intelligence_module) |
| Case Management | ✅ Integrated | [Investigation_Manager](https://github.com/Maliyka-L/Investigation_Manager) |

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

## Threat Intelligence

Every IP address found in an alert is checked against **VirusTotal** and **AbuseIPDB**, then given a risk score from 0 to 100 and a level (Low, Medium, High or Critical), with likely MITRE ATT&CK techniques.

- **Private IPs** (such as `10.x.x.x` and `192.168.x.x`) are recognised and skipped, because they can't be looked up
- **Results are cached** in `data/indicators.json` for 24 hours, so each IP is only looked up once
- **At most 4 IPs are looked up per page load**, to stay within VirusTotal's free limit of 4 lookups a minute; any others wait for the next refresh
- **Any IP rated High or Critical** raises a new Critical alert from `threat_intelligence`
- **If a lookup fails** (no keys, a bad key or no internet), the SIEM carries on and shows the reason, and the IP is tried again next time

The **Threat Intelligence** page lists every IP with its status, risk score, VirusTotal detections, AbuseIPDB score, country, report count, MITRE techniques and how many alerts it appears in.

Settings such as the cache time, the lookup limit and which risk levels raise an alert are in `config/threat_intelligence.json`.

### API keys

Both services have free accounts. Copy `.env.example` to `.env` and add your keys:

```
VT_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

The `.env` file is in `.gitignore`, so your keys never go to GitHub. Without keys, everything else still works and public IPs show "API keys not set".

## Case Management

High and Critical alerts can be turned into cases in [Investigation_Manager](https://github.com/Maliyka-L/Investigation_Manager), using its API.

- The **Cases** page lists every High and Critical alert that doesn't have a case yet
- Clicking **Create Cases** sends each one to Investigation Manager, with a title, severity, description, the IP as an IOC and any MITRE ATT&CK techniques
- **Each alert only becomes one case.** The SIEM remembers which alerts already have a case in `data/cases.json`, so pressing the button again won't create duplicates
- Every alert with a case shows its case ID on the dashboard and alerts page, linking straight to the case in Investigation Manager
- **If something goes wrong** (Investigation Manager isn't running, the API key is wrong or its API is switched off), the SIEM carries on and shows the reason

Which severities become cases is set in `config/case_management.json`.

### Connecting to Investigation Manager

Investigation Manager runs on port 5000, so the SIEM runs on port **5001**.

1. Pick an API key (any long random text) and add it to the SIEM's `.env`:

   ```
   IM_URL=http://127.0.0.1:5000
   IM_API_KEY=your-chosen-key
   ```

2. Start Investigation Manager in its own terminal with the **same** key:

   ```powershell
   $env:IM_API_KEY="your-chosen-key"   # Windows PowerShell
   python app.py
   ```

3. Start the SIEM in a second terminal, open the **Cases** page and click **Create Cases**.

## How alerts come together

Both modules produce alerts in the same standard format, so the SIEM can show them side by side:

| Field | Meaning |
|---|---|
| `source` | Which module raised it (`log_analysis`, `alert_engine` or `threat_intelligence`) |
| `time` | When the activity happened |
| `ip` | The IP address involved, if any |
| `type` | The detection rule |
| `severity` | `low`, `medium`, `high` or `critical` |
| `reason` | What was detected |
| `mitre` | MITRE ATT&CK technique, where mapped |

Alert Engine alerts also carry extra details where relevant, such as the username, host or command, and every alert with an IP carries its threat intelligence result.

The dashboard shows totals for each severity, the number of malicious IPs and the number of cases created, and the alerts page lists every alert from all modules, most severe first.

## Running it locally

```bash
git clone https://github.com/Maliyka-L/ThreatHunter_SIEM.git
cd ThreatHunter_SIEM
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux
pip install -r requirements.txt
copy .env.example .env       # then add your API keys to .env
python app.py
```

Then open http://127.0.0.1:5001 in your browser. To use a different port, set `SIEM_PORT` before starting it.

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
│   ├── alert_engine.json      # host event rule settings
│   ├── threat_intelligence.json  # cache and lookup settings
│   └── case_management.json   # which alerts become cases
├── logs/
│   ├── web/                   # sample web server logs
│   └── host/                  # sample host events
├── modules/
│   ├── log_analysis.py        # web log detection
│   ├── alert_engine.py        # host event detection and correlation
│   ├── threat_intelligence.py # VirusTotal and AbuseIPDB enrichment
│   └── case_management.py     # sends alerts to Investigation Manager
├── data/
│   ├── indicators.json        # threat intelligence cache
│   └── cases.json             # which alerts already have a case
└── templates/
    ├── dashboard.html
    ├── alerts.html
    ├── threats.html
    └── cases.html
```

## Licence

MIT
