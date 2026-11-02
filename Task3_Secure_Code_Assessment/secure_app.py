"""Fixed version of vulnerable_app.py with the recommended secure coding practices applied."""
import os
import re
import sqlite3
import subprocess
from pathlib import Path

from flask import Flask, abort, request, send_from_directory
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ["APP_SECRET_KEY"]         # F1: secret from environment, not source code
DB = "users.db"
UPLOAD_DIR = Path("uploads").resolve()
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
failed = {}   # simple in-memory lockout counter (use Flask-Limiter in production)


def db():
    return sqlite3.connect(DB)


@app.route("/register", methods=["POST"])
def register():
    user = request.form["username"]
    pw = generate_password_hash(request.form["password"])      # F2: salted, slow hash
    conn = db()
    conn.execute("INSERT INTO users(username, password) VALUES (?, ?)", (user, pw))   # F3: parameterised query
    conn.commit()
    return "registered"


@app.route("/login", methods=["POST"])
def login():
    user = request.form["username"]
    if failed.get(user, 0) >= 5:                               # F4: lockout after repeated failures
        abort(429)
    row = db().execute("SELECT password FROM users WHERE username=?", (user,)).fetchone()
    if row and check_password_hash(row[0], request.form["password"]):
        failed.pop(user, None)
        return "welcome"
    failed[user] = failed.get(user, 0) + 1
    return "invalid credentials", 401


@app.route("/search")
def search():
    term = request.args.get("q", "")
    return f"<h1>Results for {escape(term)}</h1>"              # F5: output encoding


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.match(host):                                 # F6: validate input, no shell
        abort(400)
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return out.stdout


@app.route("/download")
def download():
    return send_from_directory(UPLOAD_DIR, request.args.get("file", ""))   # F7: blocks path traversal


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)                      # F8: no debug, localhost only
