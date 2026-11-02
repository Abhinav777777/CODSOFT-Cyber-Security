"""
Intentionally VULNERABLE sample app, used only as the target of the secure code assessment.
Do NOT deploy this.
"""
import hashlib
import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
app.secret_key = "supersecret123"          # V1: hard-coded secret
DB = "users.db"


def db():
    return sqlite3.connect(DB)


@app.route("/register", methods=["POST"])
def register():
    user = request.form["username"]
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()   # V2: weak hash, no salt
    conn = db()
    conn.execute(f"INSERT INTO users(username, password) VALUES ('{user}', '{pw}')")  # V3: SQL injection
    conn.commit()
    return "registered"


@app.route("/login", methods=["POST"])
def login():
    user = request.form["username"]
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()
    query = "SELECT * FROM users WHERE username='" + user + "' AND password='" + pw + "'"  # V3
    row = db().execute(query).fetchone()
    return "welcome" if row else "invalid"           # V4: no rate limiting / lockout


@app.route("/search")
def search():
    term = request.args.get("q", "")
    return f"<h1>Results for {term}</h1>"             # V5: reflected XSS


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c 1 " + host, shell=True)   # V6: command injection


@app.route("/download")
def download():
    name = request.args.get("file", "")
    with open(os.path.join("uploads", name), "rb") as f:               # V7: path traversal
        return f.read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)       # V8: debug mode exposed on all interfaces
