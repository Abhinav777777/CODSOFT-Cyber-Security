# Task 3 - Secure Code Assessment
CODSOFT Cyber Security Internship

Security review of a small Flask app: find vulnerabilities, document them, and fix them.

| File | Purpose |
|---|---|
| `vulnerable_app.py` | Sample app with 8 deliberate flaws (do not deploy) |
| `secure_app.py` | Same app with every flaw fixed |
| `REPORT.md` | Vulnerability report with CWE/OWASP mapping and fixes |
| `bandit_before.txt` / `bandit_after.txt` | Static analysis output before and after |

## Reproduce
```bash
pip install bandit flask
bandit -r vulnerable_app.py   # many findings
bandit -r secure_app.py       # far fewer / none
```
