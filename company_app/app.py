"""The fictional company's internal app (runs in the lab's ``app`` namespace).

Its only job in the demo is to prove that legitimate traffic still works:
an employee calls ``GET /api/records`` and the app reads the ``records``
table from PostgreSQL (employee -> app on 8080, then app -> db on 5432).

Settings come from the environment (scripts/setup_lab.sh passes them):
APP_IP, APP_SERVICE_PORT, DB_HOST (or DB_IP), DB_PORT, DB_NAME, DB_USER, DB_PASSWORD.
"""
from __future__ import annotations

import os

import psycopg
from flask import Flask, jsonify

app = Flask(__name__)


def _db_settings() -> dict:
    return {
        "host": os.environ.get("DB_HOST") or os.environ.get("DB_IP", "10.10.30.10"),
        "port": int(os.environ.get("DB_PORT", "5432")),
        "dbname": os.environ.get("DB_NAME", "company"),
        "user": os.environ.get("DB_USER", "app_user"),
        "password": os.environ.get("DB_PASSWORD", ""),
        # Fail fast when the firewall blocks app -> db, so callers get a 500, not a hang.
        "connect_timeout": int(os.environ.get("DB_CONNECT_TIMEOUT", "3")),
        "sslmode": "disable",
        "application_name": "company_app",
    }


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.get("/api/records")
def records():
    try:
        with psycopg.connect(**_db_settings()) as conn, conn.cursor() as cur:
            cur.execute("SELECT id, full_name, department, email FROM records ORDER BY id")
            cols = [c.name for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    except psycopg.Error as exc:
        msg = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
        return jsonify(ok=False, error=f"database unavailable: {msg}"), 500
    return jsonify(ok=True, count=len(rows), records=rows)


if __name__ == "__main__":
    app.run(host=os.environ.get("APP_IP", "10.10.20.10"),
            port=int(os.environ.get("APP_SERVICE_PORT", "8080")),
            threaded=True, use_reloader=False)
