import datetime


def run_detection(log_path):

    # Temporary SIEM integration using your existing alert structure.
    # Later we'll move all detection functions into this module.

    alerts = [

        {
            "ip": "192.168.1.20",
            "time": datetime.datetime.now(),
            "reason": "5 failed login attempts",
            "type": "bruteforce",
            "severity": "high"
        },

        {
            "ip": "192.168.1.55",
            "time": datetime.datetime.now(),
            "reason": "Accessed /admin page",
            "type": "admin_access",
            "severity": "medium"
        }

    ]

    return alerts