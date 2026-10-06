"""Write a human-readable security report for one app: runs/report.md.

It reads what the pipeline already produced and explains each finding for a developer: where the problem
is, what is wrong, why the agent believes it (scanner, checker verdict, the rule the route breaks), the
evidence (the request replay sent and what happened), and how to fix it. Nothing new is decided here: no
model call, no new judgement. Findings that point at the same problem are shown once.

Run from the app folder (run.sh does this after replay):
  python3 ../tools/report.py                    # runs/merged.json + runs/replay.json -> runs/report.md
  python3 ../tools/report.py --out somewhere.md
"""
import argparse
import datetime
import json
from pathlib import Path

# Weakness types the pipeline reports, in plain words. Severity is an estimate from the weakness type
# alone (not from the app's context), so the report labels it as such.
CWE = {
    "CWE-78": ("OS command injection", "critical",
               "Text the visitor controls is pasted into a shell command, so they can run their own commands "
               "on the server.",
               "Do not build shell strings. Call the program with a fixed argument list and `shell=False` "
               "(`subprocess.run([...])`), and allow-list any value that selects an option."),
    "CWE-77": ("Command injection", "critical",
               "Text the visitor controls ends up inside a command the server runs.",
               "Pass arguments as a list without a shell, and allow-list values."),
    "CWE-94": ("Code injection / debug console", "critical",
               "The visitor can make the server run code. For Flask this includes `debug=True`, which exposes "
               "an interactive console on errors.",
               "Never evaluate visitor input as code. Run Flask with `debug=False` outside development and set "
               "it from the environment."),
    "CWE-95": ("Eval injection", "critical", "Visitor input reaches `eval`/`exec`.",
               "Remove `eval`/`exec` on input; parse the data with a safe parser instead."),
    "CWE-96": ("Template injection", "critical",
               "Visitor input becomes part of a template's source, so template code in it is executed "
               "(server-side template injection).",
               "Use a fixed template and pass the input as a variable: `render_template_string(TEMPLATE, "
               "message=msg)`, never `render_template_string(msg)`."),
    "CWE-1336": ("Template injection", "critical",
                 "Visitor input becomes part of a template's source, so template code in it is executed.",
                 "Use a fixed template and pass the input as a variable."),
    "CWE-502": ("Insecure deserialisation", "critical",
                "Data from the visitor is unpickled. A crafted pickle runs arbitrary code when it is loaded.",
                "Never `pickle.loads` data that came from a client. Store the data server-side (session or "
                "database) or use JSON, and sign anything that must round-trip through the client."),
    "CWE-89": ("SQL injection", "high",
               "Visitor input is pasted into an SQL string, so it can change the query: read other tables, "
               "bypass a login, or modify data.",
               "Use parameterised queries (`db.execute('... WHERE name LIKE ?', (f'%{term}%',))`); never "
               "format input into SQL text."),
    "CWE-22": ("Path traversal", "high",
               "A file name from the visitor is used to open a file, so `../` can reach files outside the "
               "intended folder, such as source code or configuration.",
               "Use `werkzeug.utils.secure_filename` and `send_from_directory`, or check that the resolved "
               "path stays inside the base folder."),
    "CWE-639": ("Access to another user's record (IDOR)", "high",
                "The route loads a record by the id in the request but never checks that it belongs to the "
                "logged-in user, so changing the id shows or changes someone else's data.",
                "Restrict the query to the current user (`... WHERE id = ? AND user_id = ?`) and return 404 "
                "when no row matches."),
    "CWE-862": ("Missing authorisation", "high",
                "The route does not check that the caller has the role it needs (for example admin or staff).",
                "Protect the route with the role check the app already uses (e.g. `@admin_required`) and test "
                "it with a normal account."),
    "CWE-863": ("Incorrect authorisation", "high", "The route's permission check lets the wrong users through.",
                "Fix the condition and test the route with each role."),
    "CWE-306": ("Missing authentication", "high",
                "The route can be used without logging in although it shows or changes private data.",
                "Add the login check (`@login_required`) and the ownership check the data needs."),
    "CWE-284": ("Improper access control", "high",
                "The route lets a user do something their role should not allow.",
                "Decide server-side who may do this, and check it in the route."),
    "CWE-285": ("Improper authorisation", "high", "The route does not enforce who may call it.",
                "Add the missing role or ownership check."),
    "CWE-915": ("Mass assignment", "high",
                "The route writes every submitted field to the database, including fields the user must not "
                "set (such as `is_admin` or `role`).",
                "Allow-list the fields a user may change and ignore everything else."),
    "CWE-269": ("Privilege escalation", "high", "A user can raise their own permissions.",
                "Allow-list editable fields; set roles only through an admin-only path."),
    "CWE-602": ("Server trusts a value the client sends", "high",
                "A value the server should decide (a price, a total, a role) is taken from the request, so the "
                "visitor can choose it.",
                "Compute the value on the server from trusted data (e.g. price from the products table) and "
                "ignore the submitted one."),
    "CWE-798": ("Hard-coded secret", "high",
                "A secret is written in the source code. Anyone with the code can forge sessions or tokens.",
                "Load secrets from the environment or a secret store, rotate the exposed one, and use a long "
                "random value (`secrets.token_hex(32)`)."),
    "CWE-259": ("Hard-coded password or key", "high",
                "A password or key is written in the source code.",
                "Move it to the environment or a secret store and rotate it."),
    "CWE-321": ("Hard-coded cryptographic key", "high", "A cryptographic key is written in the source code.",
                "Load the key from the environment and rotate it."),
    "CWE-489": ("Debug mode left on", "high",
                "The app runs with debug enabled, which shows stack traces and an interactive console.",
                "Turn debug off outside development; read the setting from the environment."),
    "CWE-352": ("Cross-site request forgery (CSRF)", "medium",
                "A request that changes data is accepted without an anti-forgery token, so another website can "
                "make a logged-in visitor's browser send it.",
                "Require a CSRF token on every state-changing form (e.g. Flask-WTF's `CSRFProtect`), use POST "
                "for changes, and set `SameSite=Lax` on the session cookie."),
    "CWE-601": ("Open redirect", "medium",
                "The app redirects to an address taken from the request, so a link on the real site can send "
                "visitors to a phishing page.",
                "Only redirect to relative paths of this site (check `urlparse(target).netloc == ''`), or to a "
                "fixed allow-list."),
    "CWE-79": ("Cross-site scripting (XSS)", "medium",
               "Visitor input is shown on a page without escaping, so script in it runs in other visitors' "
               "browsers.",
               "Let the template engine escape output; remove `|safe` / `Markup` on user content, or sanitise "
               "it with an allow-list."),
    "CWE-1284": ("Missing range check", "medium",
                 "A number from the request is used without checking its range, e.g. a negative quantity.",
                 "Validate on the server: type, minimum and maximum, before using or storing the value."),
    "CWE-20": ("Missing input validation", "medium", "A value from the request is used without validation.",
               "Validate type and range on the server."),
    "CWE-190": ("Unchecked number", "medium", "A number from the request is stored without limits.",
                "Validate type and range on the server; do not let users set balances."),
    "CWE-327": ("Weak cryptography for passwords", "medium",
                "Passwords are hashed with a fast, unsalted hash (MD5/SHA-1), which is cracked quickly if the "
                "database leaks.",
                "Use `werkzeug.security.generate_password_hash` (scrypt/pbkdf2) or bcrypt/argon2."),
    "CWE-916": ("Weak password hashing", "medium", "Passwords are hashed with a fast or unsalted hash.",
                "Use a slow, salted password hash (scrypt, bcrypt, argon2)."),
    "CWE-328": ("Weak hash", "medium", "A weak hash function is used where security depends on it.",
                "Use SHA-256 or better; for passwords a dedicated password hash."),
    "CWE-614": ("Cookie without security flags", "low",
                "A cookie is set without `Secure`/`HttpOnly`/`SameSite`.",
                "Set `secure=True, httponly=True, samesite='Lax'` when setting the cookie."),
    "CWE-704": ("Unchecked type conversion", "low",
                "A form value is converted with `float()`/`bool()`; inputs such as `nan` or `inf` pass the "
                "conversion and can break later calculations or checks.",
                "Parse with explicit validation, reject `nan`/`inf`, and check the range."),
    "CWE-93": ("Unchecked text written to a file", "low",
               "Visitor text is written to a file as is; on its own this is low risk, but check where the file "
               "name comes from.",
               "Validate the content and build the file path from trusted parts only."),
    "CWE-1395": ("Library with a known vulnerability", "medium",
                 "A pinned dependency has a published security advisory.",
                 "Upgrade to a fixed version (listed below) and re-test."),
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

# Route-by-route rule types (agent/rules.py): what breaking each one means, and the generic fix.
RULE_TYPES = {
    "who_may_call": ("Who may call this route",
                     "The route should be limited to a certain kind of user, but no line enforces that.",
                     "Add the login or role check this route needs, and test it with a lower-privileged user."),
    "whose_data": ("Whose record it is",
                   "The route works on one user's record, but nothing checks that the record belongs to the "
                   "caller.",
                   "Filter by the current user in the query (`... AND owner_id = ?`) and return 404 otherwise."),
    "csrf": ("CSRF protection",
             "The route changes data but accepts a forged request without an anti-forgery token.",
             "Require and check a CSRF token on every state-changing request."),
    "limits": ("Limits on a number",
               "A number from the visitor is used without a range check.",
               "Validate the number's type and range on the server before using it."),
    "must_not_change": ("A field the user must not set",
                        "The visitor can set a field that only the server or an admin should control.",
                        "Allow-list the fields this route may write and ignore the rest."),
    "do_not_trust": ("A value the server must not trust",
                     "A value from the visitor reaches a place where it must be decided or checked by the "
                     "server.",
                     "Decide the value on the server, or validate it strictly before use."),
}

STATUS = {
    "confirmed": "Confirmed by a real request",
    "verified": "Judged real by the checker (not tested)",
    "review": "Needs human review",
}
ACTOR = {"anon": "a logged-out visitor", "bob": "bob (a normal user)", "alice": "alice (a normal user)",
         "admin": "the admin"}


def load(path, default):
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else default


def cwe_of(finding):
    """The most severe weakness type we can explain (a finding can carry several, e.g. CWE-704 and CWE-89)."""
    known = [c for c in finding.get("cwe") or [] if c in CWE]
    if known:
        return min(known, key=lambda c: SEVERITY_ORDER[CWE[c][1]])
    return (finding.get("cwe") or [None])[0]


def same_problem(a, b):
    """Two findings describe one problem: same file and line within 1, or within 3 with the same weakness."""
    if a.get("file") != b.get("file") or a.get("line") is None or b.get("line") is None:
        return False
    d = abs(a["line"] - b["line"])
    return d <= 1 or (d <= 3 and bool(set(a.get("cwe") or []) & set(b.get("cwe") or [])))


def near_duplicate(a, b):
    """Two findings describe one problem: same file and line within 1, or within 3 with the same weakness."""
    if a.get("file") != b.get("file") or a.get("line") is None or b.get("line") is None:
        return False
    return abs(a["line"] - b["line"]) <= 5 and bool(set(a.get("cwe") or []) & set(b.get("cwe") or []))


def status_of(finding):
    if finding.get("tool") in ("rule-check", "replay"):
        return {"confirmed": "confirmed"}.get(finding.get("confidence"), "review")
    verdict = ((finding.get("extra") or {}).get("verification") or {}).get("verdict")
    return "verified" if verdict == "real" else "review"


def route_at(cards, file, line):
    for c in cards:
        if c.get("file") == file and line and c["lines"][0] <= line <= c["lines"][1]:
            return c["id"]
    return None


def excerpt(file, line, around=2):
    p = Path(file)
    if not line or not p.exists():
        return None
    text = p.read_text(errors="replace").splitlines()
    lo, hi = max(1, line - around), min(len(text), line + around)
    width = len(str(hi))
    return "\n".join(f"{'>' if n == line else ' '} {n:>{width}} | {text[n - 1]}" for n in range(lo, hi + 1))


def describe_request(req):
    who = ACTOR.get(req.get("actor"), req.get("actor") or "someone")
    what = f"`{req.get('method', '?')} {req.get('url', '?')}`"
    if req.get("value"):
        what += f" with a crafted `{req['value']}`"
    if req.get("targets"):
        what += f", aiming at {req['targets']}"
    if not req.get("result"):
        return f"As {who}: {what} — not sent, replay has no test for this kind of value yet"
    out = f"As {who}: {what} → `{req['result']}`"
    if req.get("changed"):
        out += f"; changed: {', '.join(req['changed'])}"
    return out


def checker_evidence(f):
    v = (f.get("extra") or {}).get("verification") or {}
    stage = v.get("stage") or ""
    tools = f"{f.get('tool')} ({', '.join(r for r in (f.get('rule_id') or []) if r)})"
    lines = [f"- **Flagged by:** {tools}: {f.get('title', '').strip()}"]
    if stage == "advisory":
        lines.append("- **Checker:** a published advisory lists this exact version, so no judgement is needed.")
    elif stage == "rule":
        lines.append(f"- **Checker (fixed rule, no model):** {v.get('reason')}.")
    elif stage.startswith("llm"):
        votes = v.get("votes") or []
        agree = sum(x == v.get("verdict") for x in votes)
        lines.append(f"- **Checker (local model, {agree}/{len(votes)} votes \"{v.get('verdict')}\""
                     f"{', after a second round with more context' if 'escalated' in stage else ''}):**")
        for key, label in (("source", "where the data comes from"), ("path", "how it reaches this line"),
                           ("protection", "what protects it")):
            if v.get(key):
                lines.append(f"    - {label}: {v[key]}")
    n = (f.get("extra") or {}).get("n_warnings", 1)
    if n > 1:
        lines.append(f"- {n} scanner warnings point at this problem and were merged into one.")
    return lines


def rule_evidence(f):
    e = f.get("extra") or {}
    lines = [f"- **Rule this route must follow:** {e.get('rule')}"]
    if e.get("verdict") == "uncertain":
        lines.append(f"- **Which line enforces it?** The model's answer failed the code check ({e.get('reason')}), "
                     "so the rule is treated as not enforced.")
    elif e.get("reason"):
        lines.append(f"- **Which line enforces it?** None, according to the model: {e['reason']}")
    r = e.get("replay") or {}
    if r.get("request"):
        lines.append(f"- **Replay:** {describe_request(r['request'])}.")
    if r.get("why"):
        lines.append(f"- **Outcome:** {r['why']}.")
    return lines


def is_rule(f):
    return f.get("tool") in ("rule-check", "replay")


def group(findings):
    """Attach each route-rule finding to the scanner finding on the same problem, if there is one."""
    groups = []
    scanner = sorted((f for f in findings if not is_rule(f)), key=lambda f: (f.get("file") or "", f.get("line") or 0))
    for f in scanner:
        home = next((g for g in groups if near_duplicate(f, g[0])), None)
        if home is not None:
            home.append(f)
        else:
            groups.append([f])
    for f in (f for f in findings if is_rule(f)):
        home = next((g for g in groups if not is_rule(g[0]) and same_problem(f, g[0])), None)
        if home is not None:
            home.append(f)
        else:
            groups.append([f])
    return groups


def summarise(g, cards):
    lead = g[0]
    statuses = [status_of(f) for f in g]
    status = "confirmed" if "confirmed" in statuses else "verified" if "verified" in statuses else "review"
    c = cwe_of(lead)
    rule_type = lead.get("rule_id") if lead.get("tool") in ("rule-check", "replay") else None
    name, severity, what, fix = CWE.get(c, (lead.get("title") or c or "Finding", "unknown", None, None))
    label_note = None
    if rule_type in RULE_TYPES and (c not in CWE or (rule_type == "do_not_trust" and status != "confirmed")):
        # The weakness label on an untested "do not trust" finding is the model's guess and is sometimes
        # wrong (e.g. a client-sent total labelled as command injection). The rule itself is reliable.
        name, what, fix = RULE_TYPES[rule_type]
        severity = "unknown" if c not in CWE else severity
        label_note = c
        c = None
    route = next((r for f in g for r in [(f.get("extra") or {}).get("route")] if r), None) \
        or route_at(cards, lead.get("file"), lead.get("line"))
    return {"findings": g, "status": status, "cwe": c, "name": name, "severity": severity, "what": what,
            "fix": fix, "route": route, "rule_type": rule_type, "label_note": label_note}


def render_problem(n, p):
    f = p["findings"][0]
    where = f"`{f['file']}:{f['line']}`" if f.get("line") else f"`{f.get('file')}`"
    out = [f"### {n}. {p['name']}" + (f" on `{p['route']}`" if p["route"] else ""), "",
           f"**{STATUS[p['status']]}** · severity estimate: {p['severity']}"
           + (f" · [{p['cwe']}](https://cwe.mitre.org/data/definitions/{p['cwe'].split('-')[1]}.html)"
              if p["cwe"] and p["cwe"].startswith("CWE-") else ""), "",
           f"**Where:** {where}", ""]
    code = excerpt(f.get("file"), f.get("line"))
    if code:
        out += ["```", code, "```", ""]
    if p["what"]:
        out += [f"**What is wrong:** {p['what']}", ""]
    if p.get("label_note"):
        out += [f"*The model labelled this {p['label_note']}; that label was not tested and may be wrong, so the "
                "rule below is the better description.*", ""]
    out.append("**Why the agent reports it:**")
    for g in p["findings"]:
        lines = rule_evidence(g) if is_rule(g) else checker_evidence(g)
        if not is_rule(g) and g is not f and g.get("line") != f.get("line"):
            lines[0] = lines[0].replace("**Flagged by:**", f"**Also flagged, at line {g.get('line')}:**", 1)
        out += lines
    out.append("")
    if p["fix"]:
        out += [f"**How to fix:** {p['fix']}", ""]
    return out


def render_csrf(problems):
    out = [f"### CSRF: {len(problems)} state-changing route(s) accept forged requests", "",
           "**What is wrong:** " + CWE["CWE-352"][2], "",
           "| Route | Status | Replay | Outcome |", "| --- | --- | --- | --- |"]
    for p in sorted(problems, key=lambda p: ({"confirmed": 0, "verified": 1}.get(p["status"], 2), p["route"] or "")):
        r = ((p["findings"][0].get("extra") or {}).get("replay") or {})
        req = r.get("request") or {}
        out.append(f"| `{p['route']}` | {STATUS[p['status']]} | `{req.get('method', '')} {req.get('url', '')}` as "
                   f"{req.get('actor', '?')} → `{req.get('result', '')}` | {r.get('why', '')} |")
    out += ["", "**How to fix:** " + CWE["CWE-352"][3], ""]
    return out


def render_dependencies(deps):
    out = ["## Outdated libraries", "",
           "Each pinned version below has a published security advisory (found by pip-audit; no model involved).",
           "", "| Package | Pinned | Advisories | Fixed in |", "| --- | --- | --- | --- |"]
    for f in deps:
        e = f.get("extra") or {}
        ids = e.get("cves") or [r for r in (f.get("rule_id") or [])]
        out.append(f"| {e.get('package', '?')} | {e.get('version', '?')} | {', '.join(ids)} | "
                   f"{', '.join(e.get('fix_versions') or []) or '?'} |")
    return out + ["", "**How to fix:** upgrade to a fixed version and re-run the tests.", ""]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--merged", default="runs/merged.json")
    ap.add_argument("--replay", default="runs/replay.json")
    ap.add_argument("--out", default="runs/report.md")
    args = ap.parse_args()

    merged, replayed = load(args.merged, []), load(args.replay, [])
    cards = load("runs/routecards.json", [])
    log = load("runs/replay_log.json", [])
    app = Path.cwd().name

    deps = [f for f in merged if f.get("tool") == "pip-audit"]
    problems = [summarise(g, cards) for g in group([f for f in merged if f.get("tool") != "pip-audit"] + replayed)]
    csrf = [p for p in problems if p["rule_type"] == "csrf" and len(p["findings"]) == 1]
    rest = [p for p in problems if p not in csrf]
    rest.sort(key=lambda p: ({"confirmed": 0, "verified": 1, "review": 2}[p["status"]],
                             SEVERITY_ORDER.get(p["severity"], 9), p["findings"][0].get("file") or "",
                             p["findings"][0].get("line") or 0))
    count = {s: sum(p["status"] == s for p in problems) for s in STATUS}

    out = [f"# Security report: {app}", "",
           f"Generated by routeguard on {datetime.date.today().isoformat()} from `{args.merged}` and "
           f"`{args.replay}`. Every finding below comes from the saved pipeline outputs; this report adds no "
           "new judgement.", "",
           "| | Problems |", "| --- | --- |",
           f"| {STATUS['confirmed']}: the attack was sent to a local copy of the app and worked | "
           f"{count['confirmed']} |",
           f"| {STATUS['verified']}: a scanner flagged it and the checker kept it, but no request tried it | "
           f"{count['verified']} |",
           f"| {STATUS['review']}: likely, but no automatic test could settle it | {count['review']} |",
           f"| Outdated libraries with published advisories | {len(deps)} |", "",
           "Severity is an estimate from the type of weakness only; how bad a problem is in practice depends "
           "on what the app protects.", ""]

    out += ["## Problems", ""]
    for i, p in enumerate(rest, 1):
        out += render_problem(i, p)
    if csrf:
        out += render_csrf(csrf)
    if deps:
        out += render_dependencies(deps)

    cleared = [x for x in log if x.get("verdict") == "dropped"]
    if cleared:
        out += ["## Suspicions that were tested and cleared", "",
                "The model suspected these rules were broken. Replay tried each one and the app held, so they "
                "are not reported as problems.", "", "| Route | Rule | What replay saw |", "| --- | --- | --- |"]
        out += [f"| `{x['route']}` | {RULE_TYPES.get(x['rule_type'], (x['rule_type'],))[0]} | {x['why']} |"
                for x in cleared]
        out.append("")

    out += ["## What this report does not cover", "",
            "routeguard looks at what scanners flag and at each route of the app. It does not yet examine code "
            "that runs outside routes (start-up settings, after-request hooks such as CORS or CSP headers, "
            "logging), and it does not check how passwords are stored unless a scanner flags a weak hash. "
            "Absence from this report is not proof that a problem is absent.", ""]

    Path(args.out).write_text("\n".join(out))
    print(f"{len(rest) + len(csrf)} problems ({count['confirmed']} confirmed, {count['verified']} verified, "
          f"{count['review']} for review), {len(deps)} outdated libraries -> {args.out}")


if __name__ == "__main__":
    main()
