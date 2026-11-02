# Task 3 - Secure Code Assessment Report
CODSOFT Cyber Security Internship

**Target:** `vulnerable_app.py` (Python / Flask web app, about 60 lines)
**Method:** Manual code review plus static analysis with **Bandit** (`bandit -r vulnerable_app.py`)
**Standards used:** OWASP Top 10 (2021) and CWE
**Scope:** Source code only. No testing of third-party systems.

## 1. Summary of findings
| ID | Vulnerability | Location | CWE | OWASP 2021 | Severity | Found by |
|---|---|---|---|---|---|---|
| V1 | Hard-coded secret key | `app.secret_key` | CWE-798 | A07 | Medium | Bandit + manual |
| V2 | Weak password hashing (MD5, unsalted) | `register`, `login` | CWE-327 / 916 | A02 | High | Bandit + manual |
| V3 | SQL injection | `register`, `login` | CWE-89 | A03 | Critical | Bandit (B608) + manual |
| V4 | No brute-force protection | `login` | CWE-307 | A07 | Medium | Manual |
| V5 | Reflected cross-site scripting | `search` | CWE-79 | A03 | High | Manual |
| V6 | OS command injection | `ping` | CWE-78 | A03 | Critical | Bandit (B602) + manual |
| V7 | Path traversal | `download` | CWE-22 | A01 | High | Manual |
| V8 | Debug mode on all interfaces | `app.run` | CWE-489 | A05 | High | Bandit (B201, B104) |

Totals: 2 Critical, 4 High, 2 Medium. Note that Bandit caught only some of these. Logic and
output flaws (V4, V5, V7) were found by manual review, which is why both methods are used.

## 2. Findings and fixes

### V1 Hard-coded secret key (Medium)
**Issue:** The Flask secret key is in the source code, so anyone with repository access can forge session cookies.
**Fix:** Load it from an environment variable or secrets manager, and rotate it if it was ever committed.
```python
app.secret_key = os.environ["APP_SECRET_KEY"]
```

### V2 Weak password hashing (High)
**Issue:** MD5 is fast and unsalted, so leaked hashes can be cracked in seconds with rainbow tables or GPUs.
**Fix:** Use a salted, deliberately slow algorithm (scrypt, bcrypt, Argon2 or PBKDF2).
```python
pw = generate_password_hash(password)
check_password_hash(stored, password)
```

### V3 SQL injection (Critical)
**Issue:** User input is concatenated into SQL. Entering `' OR '1'='1` as the username can bypass login, and other payloads can read or destroy data.
**Fix:** Use parameterised queries and never build SQL with string formatting.
```python
conn.execute("SELECT password FROM users WHERE username=?", (user,))
```

### V4 No brute-force protection (Medium)
**Issue:** Unlimited login attempts allow password guessing and credential stuffing.
**Fix:** Add rate limiting (for example Flask-Limiter), account lockout or back-off, CAPTCHA, and MFA.

### V5 Reflected XSS (High)
**Issue:** The `q` parameter is placed into HTML unescaped, so a crafted link can run JavaScript in a victim's browser.
**Fix:** Escape output (or use Jinja2 templates, which auto-escape) and add a Content-Security-Policy header.
```python
return f"<h1>Results for {escape(term)}</h1>"
```

### V6 OS command injection (Critical)
**Issue:** `shell=True` with user input lets an attacker append commands, for example `host=8.8.8.8;id`.
**Fix:** Validate input against an allow-list pattern and call the program with an argument list and no shell.
```python
subprocess.run(["ping", "-c", "1", host], timeout=5)
```

### V7 Path traversal (High)
**Issue:** `file=../../etc/passwd` escapes the uploads folder and exposes arbitrary files.
**Fix:** Use `send_from_directory`, which rejects traversal, and keep an allow-list of permitted files.

### V8 Debug mode exposed (High)
**Issue:** Flask debug mode shows stack traces and offers an interactive debugger, and binding to `0.0.0.0` exposes it to the network.
**Fix:** Use `debug=False`, bind to localhost behind a production server (gunicorn plus a reverse proxy), and log errors instead of displaying them.

## 3. Verification (Bandit before vs after)
| | High | Medium | Low | Total |
|---|---|---|---|---|
| `vulnerable_app.py` | 4 | 3 | 2 | 9 |
| `secure_app.py` | 0 | 0 | 3 | 3 |

The 3 remaining Low findings are informational notes about using `subprocess` and the `ping` command.
They are mitigated by the allow-list check on `host`, the absence of `shell=True`, and the timeout.
Raw output is in `bandit_before.txt` and `bandit_after.txt`.

## 4. General secure coding practices
1. Treat all input as untrusted: validate with allow-lists and encode output.
2. Use parameterised queries or an ORM.
3. Keep secrets out of code and Git (use `.gitignore` and secret scanning).
4. Hash passwords with a modern algorithm and enforce MFA where possible.
5. Apply least privilege to database accounts and file access.
6. Return generic error messages and keep details in server logs.
7. Add security headers (CSP, X-Frame-Options, HSTS) and use HTTPS.
8. Keep dependencies updated (`pip-audit`, Dependabot) and run static analysis in CI.

## 5. Tools
Bandit (static analysis), manual code review, OWASP Top 10 and CWE references.
