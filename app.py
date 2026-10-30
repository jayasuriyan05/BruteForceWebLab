from flask import Flask, render_template, request

from database import (
    init_db,
    log_login,
    get_logs,
    create_alert,
    get_alerts
)

app = Flask(__name__)

# =========================
# LOGIN CREDENTIALS
# =========================

USERNAME = "admin"
PASSWORD = "aa78"


# =========================
# SECURITY SETTINGS
# =========================

MAX_ATTEMPTS = 3

# Number of failed attempts required
# to generate a brute-force alert
BRUTE_FORCE_THRESHOLD = 3


# =========================
# LAB STATE
# =========================

failed_attempts = 0
account_locked = False


# =========================
# INITIALIZE DATABASE
# =========================

init_db()


# =========================
# LOGIN PAGE
# =========================

@app.route("/")
def home():

    return render_template("login.html")


# =========================
# LOGIN PROCESS
# =========================

@app.route("/login", methods=["POST"])
def login():

    global failed_attempts
    global account_locked

    username = request.form.get("username")
    password = request.form.get("password")

    ip_address = request.remote_addr


    # -------------------------
    # CHECK ACCOUNT LOCK
    # -------------------------

    if account_locked:

        log_login(
            username,
            "BLOCKED",
            ip_address
        )

        return """
        <h2>Account Locked</h2>

        <p>
        Too many failed login attempts were detected.
        </p>

        <p>
        The account has been temporarily locked.
        </p>

        <a href="/">Back to Login</a>
        """


    # -------------------------
    # SUCCESSFUL LOGIN
    # -------------------------

    if username == USERNAME and password == PASSWORD:

        failed_attempts = 0

        log_login(
            username,
            "SUCCESS",
            ip_address
        )

        # Redirect successful login
        # directly to the security dashboard

        return dashboard()


    # -------------------------
    # FAILED LOGIN
    # -------------------------

    failed_attempts += 1

    log_login(
        username,
        "FAILED",
        ip_address
    )


    # -------------------------
    # BRUTE FORCE DETECTION
    # -------------------------

    if failed_attempts >= BRUTE_FORCE_THRESHOLD:

        create_alert(
            "BRUTE_FORCE_DETECTED",
            "HIGH",
            "Multiple failed login attempts detected from the same source.",
            ip_address
        )


    # -------------------------
    # ACCOUNT LOCKOUT
    # -------------------------

    if failed_attempts >= MAX_ATTEMPTS:

        account_locked = True

        log_login(
            username,
            "ACCOUNT_LOCKED",
            ip_address
        )

        return """
        <h2>Account Locked</h2>

        <p>
        Too many failed login attempts were detected.
        </p>

        <p>
        A security alert has been generated.
        </p>

        <br>

        <a href="/dashboard">
            View Security Dashboard
        </a>

        """


    # -------------------------
    # REMAINING ATTEMPTS
    # -------------------------

    remaining = MAX_ATTEMPTS - failed_attempts

    return f"""
    <h2>Login Failed</h2>

    <p>
    Invalid username or password.
    </p>

    <p>
    Attempts remaining: {remaining}
    </p>

    <br>

    <a href="/">
        Try Again
    </a>

    """


# =========================
# SECURITY DASHBOARD
# =========================

@app.route("/dashboard")
def dashboard():

    logs = get_logs()

    alerts = get_alerts()


    # -------------------------
    # LOGIN STATISTICS
    # -------------------------

    total_attempts = len(logs)

    failed = sum(
        1
        for log in logs
        if log[2] == "FAILED"
    )

    successful = sum(
        1
        for log in logs
        if log[2] == "SUCCESS"
    )

    blocked = sum(
        1
        for log in logs
        if log[2] in [
            "BLOCKED",
            "ACCOUNT_LOCKED"
        ]
    )


    # -------------------------
    # ALERT STATISTICS
    # -------------------------

    total_alerts = len(alerts)

    high_alerts = sum(
        1
        for alert in alerts
        if alert[2] == "HIGH"
    )


    # -------------------------
    # SEND DATA TO DASHBOARD
    # -------------------------

    return render_template(
        "dashboard.html",

        logs=logs,

        alerts=alerts,

        total_attempts=total_attempts,

        failed=failed,

        successful=successful,

        blocked=blocked,

        total_alerts=total_alerts,

        high_alerts=high_alerts,

        account_locked=account_locked
    )


# =========================
# RESET SECURITY LAB
# =========================

@app.route("/reset")
def reset():

    global failed_attempts
    global account_locked

    failed_attempts = 0

    account_locked = False

    return """
    <!DOCTYPE html>

    <html>

    <head>

        <title>Security Lab Reset</title>

        <style>

            body {
                background: #0f172a;
                color: white;
                font-family: Arial;
                text-align: center;
                padding-top: 100px;
            }

            h1 {
                color: #38bdf8;
            }

            a {
                display: inline-block;
                margin-top: 20px;
                padding: 12px 20px;
                background: #0284c7;
                color: white;
                text-decoration: none;
                border-radius: 6px;
            }

        </style>

    </head>

    <body>

        <h1>Security Lab Reset</h1>

        <p>
            Account lockout has been reset successfully.
        </p>

        <a href="/">
            Return to Login
        </a>

    </body>

    </html>
    """


# =========================
# RUN APPLICATION
# =========================

if __name__ == "__main__":

    app.run(
        debug=True
    )