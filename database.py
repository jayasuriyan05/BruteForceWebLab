import sqlite3
from datetime import datetime

DATABASE = "security_logs.db"


def init_db():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Login event table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            status TEXT,
            ip_address TEXT,
            timestamp TEXT
        )
    """)

    # Security alert table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            description TEXT,
            ip_address TEXT,
            timestamp TEXT
        )
    """)

    connection.commit()
    connection.close()


def log_login(username, status, ip_address):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO login_logs
        (username, status, ip_address, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        status,
        ip_address,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def get_logs():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, username, status, ip_address, timestamp
        FROM login_logs
        ORDER BY id DESC
    """)

    logs = cursor.fetchall()

    connection.close()

    return logs


def create_alert(alert_type, severity, description, ip_address):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_alerts
        (alert_type, severity, description, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        alert_type,
        severity,
        description,
        ip_address,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def get_alerts():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, alert_type, severity, description, ip_address, timestamp
        FROM security_alerts
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts