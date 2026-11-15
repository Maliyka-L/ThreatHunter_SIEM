from flask import Flask, redirect, render_template, request, url_for
import os

from modules import alert_engine, case_management, log_analysis, threat_intelligence

app = Flask(__name__)

WEB_LOG_PATH = os.environ.get("SIEM_WEB_LOG", "logs/web/sample.log")
HOST_LOG_PATH = os.environ.get("SIEM_HOST_LOG", "logs/host/sample_logs.json")

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def collect_alerts():
    alerts = log_analysis.run_detection(WEB_LOG_PATH) + alert_engine.run_detection(HOST_LOG_PATH)
    alerts, intel = threat_intelligence.enrich_alerts(alerts)

    alerts.sort(key=lambda a: a.get("time", ""))
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.get("severity"), 0), reverse=True)
    case_management.attach_cases(alerts)

    return alerts, intel


@app.route("/")
def dashboard():

    alerts, intel = collect_alerts()

    metrics = {
        "total_alerts": len(alerts),

        "critical_alerts": len(
            [a for a in alerts if a["severity"] == "critical"]
        ),

        "high_alerts": len(
            [a for a in alerts if a["severity"] == "high"]
        ),

        "medium_alerts": len(
            [a for a in alerts if a["severity"] == "medium"]
        ),

        "low_alerts": len(
            [a for a in alerts if a["severity"] == "low"]
        ),

        "malicious_ips": len(
            [ip for ip, r in intel.items() if r.get("severity") in ("HIGH", "CRITICAL")]
        ),

        "cases": len(case_management.load_cases())
    }

    return render_template(
        "dashboard.html",
        metrics=metrics,
        alerts=alerts,
        im_url=case_management.get_settings()[0]
    )


@app.route("/alerts")
def alerts_page():

    alerts, intel = collect_alerts()

    return render_template(
        "alerts.html",
        alerts=alerts,
        im_url=case_management.get_settings()[0]
    )


@app.route("/threats")
def threats_page():

    alerts, intel = collect_alerts()

    alert_counts = {}
    for alert in alerts:
        if alert.get("ip"):
            alert_counts[alert["ip"]] = alert_counts.get(alert["ip"], 0) + 1

    indicators = [
        {"ip": ip, "alerts": alert_counts.get(ip, 0), **result}
        for ip, result in intel.items()
    ]
    indicators.sort(key=lambda i: (i.get("status") != "checked", -i.get("risk_score", 0), i["ip"]))

    return render_template(
        "threats.html",
        indicators=indicators
    )


@app.route("/cases")
def cases_page():

    alerts, intel = collect_alerts()
    im_url, im_key = case_management.get_settings()

    cases = sorted(
        case_management.load_cases().values(),
        key=lambda c: c.get("created", ""),
        reverse=True
    )

    waiting = [
        a for a in case_management.eligible_alerts(alerts)
        if not a.get("case_id")
    ]

    result = {
        "created": request.args.get("created"),
        "already_open": request.args.get("already_open"),
        "error": request.args.get("error", "")
    }

    return render_template(
        "cases.html",
        cases=cases,
        waiting=waiting,
        im_url=im_url,
        key_set=bool(im_key),
        result=result
    )


@app.route("/cases/sync", methods=["POST"])
def sync_cases():

    alerts, intel = collect_alerts()
    summary = case_management.create_cases(alerts)

    return redirect(url_for("cases_page", **summary))


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    port = int(os.environ.get("SIEM_PORT", "5001"))
    app.run(debug=debug_mode, port=port)
