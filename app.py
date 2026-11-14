from flask import Flask, render_template
import os

from modules import alert_engine, log_analysis

app = Flask(__name__)

WEB_LOG_PATH = os.environ.get("SIEM_WEB_LOG", "logs/web/sample.log")
HOST_LOG_PATH = os.environ.get("SIEM_HOST_LOG", "logs/host/sample_logs.json")

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def collect_alerts():
    alerts = log_analysis.run_detection(WEB_LOG_PATH) + alert_engine.run_detection(HOST_LOG_PATH)

    alerts.sort(key=lambda a: a.get("time", ""))
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.get("severity"), 0), reverse=True)

    return alerts


@app.route("/")
def dashboard():

    alerts = collect_alerts()

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
        )
    }

    return render_template(
        "dashboard.html",
        metrics=metrics,
        alerts=alerts
    )


@app.route("/alerts")
def alerts_page():

    alerts = collect_alerts()

    return render_template(
        "alerts.html",
        alerts=alerts
    )


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_mode)
