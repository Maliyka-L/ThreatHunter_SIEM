from flask import Flask, render_template
import os

from modules.log_analysis import run_detection

app = Flask(__name__)

WEB_LOG_PATH = os.environ.get("SIEM_WEB_LOG", "logs/web/sample.log")


@app.route("/")
def dashboard():

    alerts = run_detection(WEB_LOG_PATH)

    metrics = {
        "total_alerts": len(alerts),

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

    alerts = run_detection(WEB_LOG_PATH)

    return render_template(
        "alerts.html",
        alerts=alerts
    )


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_mode)
