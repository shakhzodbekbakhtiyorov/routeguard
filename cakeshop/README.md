# cakeshop: a deliberately vulnerable Flask app

A small cake-shop web app (products, search, reviews, cart, checkout, orders, invoices, admin panel). It contains **19 planted vulnerabilities** and **8 decoys**. The decoys are code that looks dangerous but is safe. Together they serve as a labelled test target for the security agent.

> For local testing only. It binds to 127.0.0.1. Never deploy it or expose it to a network.

## Run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
flask --app run init-db      # creates the database with demo users, cakes and orders
python run.py                # http://127.0.0.1:5000
```

Demo users: `admin / admin123`, `alice / alice123`, `bob / bob123`.

## Ground truth

- `labels/ground_truth.json` lists every vulnerability (CWE, category, file, the line anchor, where the input comes from, whether it crosses files) and every decoy (what it looks like, why it's safe).
- `python3 ../tools/score.py --check-labels` resolves anchors to line numbers. It fails if an edit breaks a label.

**Hide `labels/` from the agent during evaluation.** The app code itself contains no comments hinting at the bugs.

## Mix of bugs

| Category | Count | Examples |
|---|---|---|
| pattern | 8 | SQLi (cross-file), SSTI, path traversal, pickle cookie, command injection, stored XSS, open redirect, MD5 passwords |
| logic | 6 | IDOR, client-side price, negative quantity, missing admin check, mass assignment to `is_admin`, no CSRF |
| config | 2 | hardcoded `SECRET_KEY`, debug mode |
| dependency | 3 | old Flask, Werkzeug, Jinja2 |
