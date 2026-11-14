from flask import Flask, render_template
from modules.log_analysis import run_detection

app = Flask(__name__)


@app.route("/")
def dashboard():

    alerts = run_detection("data/logs/sample.log")

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

    alerts = run_detection("data/logs/sample.log")

    return render_template(
        "alerts.html",
        alerts=alerts
    )


if __name__ == "__main__":
    app.run(debug=True)