"""Agent mode: the local model DESIGNS each test; code still JUDGES it."""
import base64
import json
import os
import pickle
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # agent/
sys.path.insert(0, os.getcwd())                            # the app package
import llm
import replay as rp          # every oracle, login harness and payload is reused from here
import routecard as rc
import rules as rl
from codeindex import CodeIndex

NUM_CTX = 4096
ANSWER_TOKENS = 300

# the dangerous probes: the model picks one of these KEYS, the code owns the payload (see run_sink)
SINK_KINDS = {
    "redirect": "the value is used in a redirect -> test for an off-site (open) redirect",
    "shell": "the value reaches an OS/shell command -> test for command injection",
    "path": "the value is used as a file name or path -> test for path traversal (reading another file)",
    "deserialize": "the value comes from a cookie that is deserialised (pickle/yaml) -> test for code execution",
    "template": "the value is concatenated into a template -> test for template injection",
}

SYSTEM = """You design ONE security test for a web route, then STOP. You do NOT judge the result:
separate, trusted code runs your test and checks what happened. Choose the test parameters most
likely to prove the rule is broken, using only the facts and code shown. Use real names from the
lists given (user names, field names); never invent a name. Reply with JSON only."""


def route_fields(card):
    """Every field name the route reads (form, query, URL), for validating the model's choice."""
    names = {i["key"] for i in card["inputs"] if i["key"] not in ("*", "?")}
    names |= {p["name"] for p in card["url_params"]}
    return names


def numeric_fields(card):
    return sorted({i["key"] for i in card["inputs"] if i.get("as") in ("int", "float", "Decimal")})


def written_cols(card):
    tbl = rp.written_table(card)
    return tbl, [c for c in (card["tables"].get(tbl) or []) if c != "id"]


def facts_block(card):
    users = "; ".join(f"{u['name']} (role {u.get('role', 'user')})" for u in rp.CFG["users"])
    tbl, cols = written_cols(card)
    lines = [f"Users you can log in as: {users}",
             f"Access level this route enforces: {rp.gate_level(card)}",
             f"HTTP methods: {', '.join(card['methods'])}",
             f"Fields the route reads: {', '.join(sorted(route_fields(card))) or '(none)'}"]
    if numeric_fields(card):
        lines.append(f"Numeric fields: {', '.join(numeric_fields(card))}")
    if tbl:
        lines.append(f"Writes table {tbl}; its columns: {', '.join(cols) or '(unknown)'}")
    return "\n".join(lines)


def build_prompt(idx, route, card, facts, task):
    extra = len(facts) + len(task) + 200
    code = rl.route_prompt(idx, route, card, llm.code_budget(NUM_CTX, ANSWER_TOKENS, SYSTEM) - extra)
    return f"{code}\n\nFACTS\n{facts}\n\nTASK\n{task}"


def design(prompt, schema, validate, attempts=3):
    """Ask the model for a plan and validate it, retrying on a rejected plan or an Ollama error; returns (plan, note) or (None, why)."""
    why = ""
    for i in range(attempts):
        try:
            ans = llm.ask(SYSTEM, prompt, schema, NUM_CTX, max_tokens=ANSWER_TOKENS,
                          seed=i, temperature=0.0 if i == 0 else 0.4)
        except llm.LLMError as e:
            why = f"model call failed: {e}"
            continue
        ok, why = validate(ans)
        if ok:
            return ans, ans.get("reason", "")
        prompt += f"\n\nYour previous answer was rejected: {why}. Try again."
    return None, why


def attempt(fn, *args, **kwargs):
    """Run a request; return (response, None), or (None, 'ExcType: msg') if the app raised on hostile input."""
    try:
        return fn(*args, **kwargs), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def gate_role(name):
    return next((u.get("role", "user") for u in rp.CFG["users"] if u["name"] == name), None)


def below_gate(actor, level):
    """Is `actor` genuinely weaker than the required level? (only such a caller tests the access check)"""
    if actor == "anon":
        return level in ("logged_in_user", "admin")
    if level == "admin":
        return gate_role(actor) != "admin"
    return False                                   # any logged-in user already passes logged_in_user


def run_access(idx, app, route, card, level):
    """level is the access the route SHOULD require (the rules step's decision), not the one its code enforces."""
    if level not in ("logged_in_user", "admin"):
        return "not_applicable", "the route is public by its own rule", {}
    facts = facts_block(card)
    task = (f"RULE (who_may_call): only a '{level}' caller may use this route.\n"
            "Pick a caller who should be BLOCKED: 'anon' (not logged in), or a user whose role is "
            "below the required level. If the route takes a record id in its URL, set use_victim_record "
            "to true to point the request at the victim's own record.")
    schema = {"type": "object", "properties": {
        "actor": {"type": "string"}, "use_victim_record": {"type": "boolean"},
        "reason": {"type": "string"}}, "required": ["actor", "use_victim_record", "reason"]}

    def validate(a):
        if a["actor"] != "anon" and a["actor"] not in rp.USERS:
            return False, f"{a['actor']!r} is not one of the users (use a listed name or 'anon')"
        if not below_gate(a["actor"], level):
            return False, f"{a['actor']!r} is not below '{level}'; pick a weaker caller"
        return True, ""

    plan, note = design(build_prompt(idx, route, card, facts, task), schema, validate)
    if plan is None:
        return "plan_invalid", note, {"plan": None}
    actor = plan["actor"]
    creds = None if actor == "anon" else rp.USERS[actor]
    method = rp.pick_method(card, write=False)
    values = {}
    if plan.get("use_victim_record") and card["url_params"]:
        rid = rp.own_record_id(app, card, rp.VICTIM)
        if rid is not None:
            values[card["url_params"][0]["name"]] = rid
    url = rp.url_of(card, values)
    req = {"plan": plan, "actor": actor, "method": method, "url": url, "need": level}
    resp, err = attempt(rp.send, rp.login(app, creds), method, url, data=rp.defaults(card, "form"),
                        query=rp.defaults(card, "args") or None)
    if err:
        req["result"] = err
        return "dropped", f"the request errored before any data was returned ({err[:80]})", req
    req["result"] = rp.outcome(resp)
    if rp.is_blocked(resp):
        return "dropped", f"{actor} is blocked ({rp.outcome(resp)}) -- the access check holds", req
    body = resp.get_data(as_text=True)
    leaked = sorted(v for v in rp.victim_data(app) if v in body)
    if method == "GET" and resp.status_code == 200 and leaked:
        return "confirmed", f"{actor} (below '{level}') received {rp.VICTIM}'s data {leaked[0]!r} -- no access check", req
    return "dropped", f"{actor} not blocked ({rp.outcome(resp)}) but saw no one's private data", req


def run_ownership(idx, app, route, card):
    target = next(rp.owner_tables(card), None)
    if not card["url_params"] or not target:
        return "not_applicable", "no record id in the URL, or the table has no per-user owner column", {}
    attacker = rp.ATTACKER
    facts = facts_block(card)
    task = (f"RULE (whose_data): a caller may only touch records they own. You are logged in as "
            f"{attacker!r} (the attacker). Pick another user whose record {attacker} should not be "
            "allowed to access, and whether to read it or modify it.")
    schema = {"type": "object", "properties": {
        "victim": {"type": "string"}, "action": {"type": "string", "enum": ["read", "modify"]},
        "reason": {"type": "string"}}, "required": ["victim", "action", "reason"]}

    def validate(a):
        if a["victim"] not in rp.USERS:
            return False, f"{a['victim']!r} is not one of the users"
        if a["victim"] == attacker:
            return False, f"pick a user other than the attacker {attacker!r}"
        return True, ""

    plan, note = design(build_prompt(idx, route, card, facts, task), schema, validate)
    if plan is None:
        return "plan_invalid", note, {"plan": None}
    victim = plan["victim"]
    tbl, owner, acc_file, acc_line = target
    con = rp.connect(app)
    vrow = con.execute(f"SELECT * FROM {tbl} WHERE {owner} = ? LIMIT 1",
                       (rp.user_id(con, victim),)).fetchone()
    if vrow is None:
        return "not_applicable", f"no {tbl} row owned by {victim} to target", {"plan": plan}
    rid = vrow["id"]
    method = rp.pick_method(card, write=plan["action"] == "modify")
    req = {"plan": plan, "actor": attacker, "method": method,
           "url": rp.url_of(card, {card["url_params"][0]["name"]: rid}),
           "targets": f"{victim}'s {tbl} #{rid}", "file": acc_file, "line": acc_line}
    before = dict(vrow)
    resp, err = attempt(rp.send, rp.login(app, rp.USERS[attacker]), method, req["url"],
                        data=rp.defaults(card, "form"))
    if err:
        req["result"] = err
        return "dropped", f"the request errored before {victim}'s record was touched ({err[:70]})", req
    req["result"] = rp.outcome(resp)
    if rp.is_blocked(resp):
        return "dropped", f"{attacker} is blocked from {victim}'s {tbl} #{rid} ({rp.outcome(resp)}) -- ownership checked", req
    after = rp.connect(app).execute(f"SELECT * FROM {tbl} WHERE id = ?", (rid,)).fetchone()
    if after is None or dict(after) != before:
        what = "deleted" if after is None else "changed " + ", ".join(k for k in before if before[k] != after[k])
        return "confirmed", f"{attacker} {what} of {victim}'s {tbl} #{rid} ({rp.outcome(resp)})", req
    body = resp.get_data(as_text=True)
    leaked = [str(vrow[k]) for k in vrow.keys() if isinstance(vrow[k], str) and len(vrow[k]) > 4
              and k.lower() not in rp.OWNER_COLS and vrow[k] in body]
    if resp.status_code == 200 and leaked:
        return "confirmed", f"{attacker} read {victim}'s {tbl} #{rid}; response shows owner-only data {leaked[0]!r}", req
    return "dropped", f"{attacker} got {rp.outcome(resp)} but {victim}'s data was not disclosed", req


def run_csrf(idx, app, route, card):
    facts = facts_block(card)
    writes = [m for m in rp.WRITE_METHODS if m in card["methods"]] or [rp.pick_method(card, write=True)]
    task = ("RULE (csrf): a state-changing request forged from another website (no CSRF token, no custom "
            "headers) must be rejected. Choose which method to forge and the form values to send. Give "
            "values as a list of {field, value} using the fields the route reads.")
    schema = {"type": "object", "properties": {
        "method": {"type": "string", "enum": writes},
        "values": {"type": "array", "items": {"type": "object", "properties": {
            "field": {"type": "string"}, "value": {"type": "string"}}, "required": ["field", "value"]}},
        "reason": {"type": "string"}}, "required": ["method", "values", "reason"]}

    def validate(a):
        if a["method"] not in card["methods"]:
            return False, f"{a['method']} is not a method of this route"
        return True, ""

    plan, note = design(build_prompt(idx, route, card, facts, task), schema, validate)
    if plan is None:
        return "plan_invalid", note, {"plan": None}
    actor, creds = rp.actor_for(card)
    method = plan["method"]
    form = rp.defaults(card, "form")
    if set(rp.login_fields()) <= set(form):
        form.update(zip(rp.login_fields(), rp.USERS[rp.VICTIM]))
    if any(i["part"] == "form" and i["key"] == "*" for i in card["inputs"]):
        form.update({c: "x" for c in card["tables"].get(rp.written_table(card)) or []
                     if c != "id" and c.lower() not in rp.OWNER_COLS})
    form.update({v["field"]: v["value"] for v in plan.get("values", []) if v.get("field")})
    client = rp.login(app, creds)
    before = rp.snapshot(app)
    resp, err = attempt(rp.send, client, method, rp.url_of(card), data=form, tokens=False,
                        query=rp.defaults(card, "args") or None, headers={"Origin": "http://attacker.invalid"})
    if err:
        return "dropped", f"the forged {method} errored in the app ({err[:80]})", \
            {"plan": plan, "actor": actor, "method": method, "url": rp.url_of(card), "result": err}
    changed = [f"table {t}" for t, rows in rp.snapshot(app).items() if before.get(t) != rows]
    session_cookie = app.config.get("SESSION_COOKIE_NAME", "session")
    set_names = {c.split("=", 1)[0].strip() for c in resp.headers.getlist("Set-Cookie")}
    if set_names - {session_cookie}:
        changed.append("cookies " + ", ".join(sorted(set_names - {session_cookie})))
    req = {"plan": plan, "actor": actor, "method": method, "url": rp.url_of(card),
           "result": rp.outcome(resp), "changed": changed}
    if changed:
        return "confirmed", f"a forged {method} with no token changed {', '.join(changed)} ({rp.outcome(resp)})", req
    if set_names:
        return "uncertain", (f"the forged {method} only rewrote the session cookie ({rp.outcome(resp)}): a real "
                             "change or bookkeeping; keep for a human"), req
    return "dropped", f"the forged {method} changed nothing ({rp.outcome(resp)})", req


def sender(app, card, field):
    """Return a do(value) that sends value in field wherever the route reads it, as a caller who passes its access check."""
    actor, creds = rp.actor_for(card)
    me = actor if actor in rp.USERS else rp.ATTACKER
    my_id = rp.own_record_id(app, card, me) or 1
    method = rp.pick_method(card, rp.state_changing(card))
    parts = {i["part"] for i in card["inputs"] if i["key"] in ("*", field)}
    in_url = any(p["name"] == field for p in card["url_params"])

    def do(inject, cookies=None, login_as=None):
        form, query = rp.defaults(card, "form"), rp.defaults(card, "args")
        if login_as:
            form.update(zip(rp.login_fields(), login_as))
        if "form" in parts:
            form[field] = inject
        if "args" in parts:
            query[field] = inject
        url = rp.url_of(card, {field: inject}, my_id) if in_url else rp.url_of(card, default=my_id)
        return rp.send(rp.login(app, creds), method, url, data=form, query=query or None, cookies=cookies)

    return do, actor, me, method


def num_eq(stored, sent):
    try:
        return float(stored) == float(sent)
    except (TypeError, ValueError):
        return str(stored) == str(sent)


def run_value(idx, app, route, card, rule_type, rule_text):
    tbl, cols = written_cols(card)
    facts = facts_block(card)
    if rule_type == "limits":
        task = (f"RULE (limits): {rule_text}\nPick ONE numeric field and ONE bad value to send that the "
                "server should reject (for example -5, 0, or 999999). Write the value yourself.")
        allowed = numeric_fields(card) or sorted(route_fields(card))
    else:   # must_not_change -- mass assignment
        task = (f"RULE (must_not_change): {rule_text}\nPick ONE field the caller must NOT be able to set on "
                f"their own record (a privileged column such as is_admin, role, credit_balance) and the value "
                "to set it to (for example 1). Write the value yourself.")
        allowed = cols or sorted(route_fields(card))
    schema = {"type": "object", "properties": {
        "field": {"type": "string"}, "value": {"type": "string"}, "reason": {"type": "string"}},
        "required": ["field", "value", "reason"]}

    def validate(a):
        if rule_type == "limits" and a["field"] not in set(allowed) | route_fields(card):
            return False, f"{a['field']!r} is not a field this route reads"
        if rule_type == "must_not_change" and tbl and a["field"] not in cols:
            return False, f"{a['field']!r} is not a column of {tbl}; pick one of: {', '.join(cols)}"
        return True, ""

    plan, note = design(build_prompt(idx, route, card, facts, task), schema, validate)
    if plan is None:
        return "plan_invalid", note, {"plan": None}
    field, value = plan["field"], plan["value"]
    do, actor, me, method = sender(app, card, field)
    req = {"plan": plan, "actor": actor, "method": method, "field": field, "value": value, "type": rule_type}
    resp, err = attempt(do, value)
    if err:        # a runtime error (e.g. a DB constraint) means the app did not store the value
        req["result"] = err
        return "dropped", f"the request errored before the value was stored ({err[:80]})", req
    req["result"] = rp.outcome(resp)
    if rp.is_blocked(resp):
        return "dropped", f"the server rejected {field}={value} ({rp.outcome(resp)})", req
    if not tbl:
        return "uncertain", "request accepted but there is no table to check the stored effect", req
    con = rp.connect(app)
    cols_raw = card["tables"].get(tbl) or []
    if rule_type == "must_not_change":      # the caller's own account row, by primary key (as replay)
        lookup = "user_id" if "user_id" in cols_raw else "id"
    else:                                   # limits: a record the caller owns
        lookup = rp.owner_col(card, tbl) or ("user_id" if "user_id" in cols_raw else "id")
    try:
        rows = con.execute(f"SELECT * FROM {tbl} WHERE {lookup} = ? ORDER BY id DESC",
                           (rp.user_id(con, me),)).fetchall()
    except Exception:
        rows = con.execute(f"SELECT * FROM {tbl} ORDER BY id DESC LIMIT 1").fetchall()
    if not rows:
        return "uncertain", "value accepted but no row of the caller's was found to check", req
    row = rows[0]
    if rule_type == "must_not_change":
        if field in row.keys() and any(num_eq(r[field], value) for r in rows):
            return "confirmed", f"{me} set {tbl}.{field}={value} on their own row -- privilege change", req
        return "dropped", f"{tbl}.{field} did not take the value {value} -- the field is protected", req
    # limits: the exact value is stored, or it fed a now-out-of-range number
    if field in row.keys() and num_eq(row[field], value):
        return "confirmed", f"the server accepted and stored {tbl}.{field}={value}", req
    bad = [f"{k}={row[k]}" for k in row.keys() if str(row[k]).lstrip("-").replace(".", "", 1).isdigit()
           and float(row[k]) < 0]
    if bad:
        return "confirmed", f"the server accepted {field}={value} and stored {', '.join(bad)}", req
    return "dropped", f"the out-of-range value {value} was not stored", req


def run_sink(idx, app, route, card, rule_text):
    facts = facts_block(card)
    kinds = "\n".join(f"  {k}: {d}" for k, d in SINK_KINDS.items())
    task = (f"RULE (do_not_trust): {rule_text}\nPick ONE field the route reads and the KIND of test to run "
            f"against the place that value reaches. You do NOT write the payload -- trusted code supplies a "
            f"harmless one for the kind you choose. The kinds:\n{kinds}")
    schema = {"type": "object", "properties": {
        "field": {"type": "string"}, "sink_kind": {"type": "string", "enum": list(SINK_KINDS)},
        "reason": {"type": "string"}}, "required": ["field", "sink_kind", "reason"]}

    def validate(a):
        if a["field"] not in route_fields(card):
            return False, f"{a['field']!r} is not a field this route reads"
        return True, ""

    plan, note = design(build_prompt(idx, route, card, facts, task), schema, validate)
    if plan is None:
        return "plan_invalid", note, {"plan": None}
    field, kind = plan["field"], plan["sink_kind"]
    do, actor, me, method = sender(app, card, field)
    req = {"plan": plan, "actor": actor, "method": method, "field": field, "sink_kind": kind}
    marker = os.path.join(tempfile.mkdtemp(dir=rp.RUN_DIR), "MARKER")

    if kind == "redirect":
        evil = "http://investigate.invalid/pwned"
        login_form = set(rp.login_fields()) <= {i["key"] for i in card["inputs"] if i["part"] == "form"}
        resp, err = attempt(do, evil, login_as=rp.USERS[rp.VICTIM] if login_form else None)
        if err:
            req["result"] = err
            return "dropped", f"the request errored before any redirect ({err[:80]})", req
        req["result"] = rp.outcome(resp)
        loc = resp.headers.get("Location", "")
        if loc.startswith(evil):
            return "confirmed", f"the response redirects to the attacker URL {loc!r} -- open redirect", req
        return "dropped", f"the value was not used as an external redirect ({rp.outcome(resp)}, Location {loc!r})", req

    if kind == "shell":
        try:
            req["result"] = rp.outcome(do(f"x; touch {marker}; echo"))
        except Exception as e:
            req["result"] = f"view raised {type(e).__name__} after the command ran"
        if os.path.exists(marker):
            return "confirmed", "a shell metacharacter payload ran a command (wrote a marker file) -- command injection", req
        return "dropped", f"the payload did not run a command ({req['result']})", req

    if kind == "path":
        src_file = os.path.abspath(card["file"])
        base = next((app.config[k] for k in rp.CFG.get("file_base_keys", []) if app.config.get(k)), app.root_path)
        rel = os.path.relpath(src_file, base)
        token = next((l.strip() for l in Path(src_file).read_text().splitlines() if len(l.strip()) > 15), "def ")
        resp, err = attempt(do, rel)
        if err:
            req["result"] = err
            return "dropped", f"the request errored before the file could be read ({err[:70]})", req
        req["result"] = rp.outcome(resp)
        if resp.status_code == 200 and token in resp.get_data(as_text=True):
            return "confirmed", f"reading {rel!r} returned source code ({token!r}) -- path traversal", req
        return "dropped", f"traversal to {rel!r} did not return the file ({rp.outcome(resp)})", req

    if kind == "deserialize":
        payload = base64.b64encode(pickle.dumps(rp.MarkerFile(marker))).decode()
        try:
            req["result"] = rp.outcome(do("", cookies={field: payload}))
        except Exception as e:
            req["result"] = f"view raised {type(e).__name__} after the payload ran"
        if os.path.exists(marker):
            return "confirmed", "a crafted object in the cookie ran code (wrote a marker file) on deserialisation -- RCE", req
        return "dropped", f"the crafted payload did not execute ({req['result']})", req

    if kind == "template":
        resp, err = attempt(do, "{{7*7}}")
        if err:
            req["result"] = err
            return "dropped", f"the request errored before the template rendered ({err[:70]})", req
        req["result"] = rp.outcome(resp)
        if "49" in resp.get_data(as_text=True):
            return "confirmed", "the expression {{7*7}} rendered as 49 -- template injection", req
        return "dropped", "the expression {{7*7}} was not evaluated -- not injectable", req

    return "uncertain", f"no payload for sink kind {kind!r}", req


def investigate(idx, app, route, card, rule_type, rule_text, level):
    if rule_type == "who_may_call":
        return run_access(idx, app, route, card, level)
    if rule_type == "whose_data":
        return run_ownership(idx, app, route, card)
    if rule_type == "csrf":
        return run_csrf(idx, app, route, card)
    if rule_type in ("limits", "must_not_change"):
        return run_value(idx, app, route, card, rule_type, rule_text)
    if rule_type == "do_not_trust":
        return run_sink(idx, app, route, card, rule_text)
    return "uncertain", "no agent probe for this rule type", {}


def main():
    rp.load_config()
    rp.RUN_DIR = tempfile.mkdtemp(prefix="investigate_")
    for name, creds in rp.USERS.items():            # every test depends on the logins: check them first
        try:
            rp.login(rp.fresh_app(), creds)
        except rp.LoginFailed as e:
            shutil.rmtree(rp.RUN_DIR, ignore_errors=True)
            sys.exit(f"investigate stopped: {e}")
    llm.check_ollama()
    idx = CodeIndex(".")
    cards = {card["id"]: (route, card) for route, card in rc.all_cards(idx)}
    rules = {e["id"]: e for e in json.loads(Path("runs/rules.json").read_text())}

    jobs = [(f["extra"]["route"], f["rule_id"], f["extra"]["rule"], f)
            for f in json.loads(Path("runs/enforce.json").read_text())]
    done = {job[:3] for job in jobs}
    jobs += [(rid, "whose_data", r["rule"], None) for rid, e in rules.items() for r in e["rules"]
             if r["type"] == "whose_data" and (rid, "whose_data", r["rule"]) not in done]

    kept, log = [], []
    for route_id, rule_type, rule_text, finding in jobs:
        pair = cards.get(route_id)
        if pair is None:
            continue
        route, card = pair
        level = rules.get(route_id, {}).get("decisions", {}).get("who_may_call") \
            or ("admin" if "administ" in rule_text.lower() else "logged_in_user")   # same as replay.py
        try:
            verdict, why, req = investigate(idx, rp.fresh_app(), route, card, rule_type, rule_text, level)
        except Exception as e:
            verdict, why, req = "error", f"{type(e).__name__}: {e}", {}
        entry = {"route": route_id, "rule_type": rule_type, "rule": rule_text,
                 "from_finding": finding is not None, "verdict": verdict, "why": why, "test": req}
        log.append(entry)
        if verdict in ("confirmed", "uncertain"):
            if finding is None:                     # a whose_data rule enforce.py had accepted
                rel, line = card["file"], card["lines"][0]
                finding = {"tool": "investigate", "rule_id": rule_type,
                           "title": f"Rule not enforced: {rule_text}", "file": rel, "line": line,
                           "snippet": idx.line(rel, line).strip(), "cwe": ["CWE-639"],
                           "extra": {"route": route_id, "rule": rule_text}}
            kept.append(dict(finding, confidence=verdict, extra=dict(finding["extra"], investigate=entry)))
        print(f"  {route_id:<42} {rule_type:<16} {verdict:<13} {why[:60]}"
              + ("" if finding is not None or rule_type != "whose_data" else "  (re-check)"))

    shutil.rmtree(rp.RUN_DIR, ignore_errors=True)
    Path("runs").mkdir(exist_ok=True)
    Path("runs/investigate.json").write_text(json.dumps(kept, indent=2))
    Path("runs/investigate_log.json").write_text(json.dumps(log, indent=2))
    c = lambda *vs: sum(e["verdict"] in vs for e in log)
    print(f"\n{len(jobs)} rules investigated: {c('confirmed')} confirmed, {c('dropped')} dropped, "
          f"{c('uncertain')} uncertain, {c('plan_invalid')} the model could not design a valid test, "
          f"{c('error')} errored -> runs/investigate.json")


if __name__ == "__main__":
    main()
