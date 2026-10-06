"""Replay each finding from enforce.py as a real request and keep only the findings whose attack works."""
import ast
import base64
import html
import json
import os
import pickle
import re
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))   # agent/
sys.path.insert(0, os.getcwd())                            # the app package
import routecard as rc
from codeindex import CodeIndex

OWNER_COLS = {"user_id", "owner_id", "account_id", "author_id", "username", "user"}
ADMIN_WORDS = ("is_admin", "is_staff", "is_superuser", "is_manager", "role", "admin", "staff")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
REDIRECT = {301, 302, 303, 307, 308}
LOGIN_CHECK = re.compile(r"(\bnot\s+(g|session)\b[.\[]|\b(g|session)\b\S*\s+is\s+none)")
INPUT_TAG = re.compile(r"<input\b[^>]*>", re.I)
PASSWORD_BOX = re.compile(r"<input\b[^>]*type\s*=\s*[\"']?password", re.I)

CFG = {}              # replay_config.json
USERS = {}            # name -> (username, password)
ADMIN = ATTACKER = VICTIM = None
RUN_DIR = None        # temporary files of this run (databases, marker files), removed at the end


def load_config(path="replay_config.json"):
    global CFG, ADMIN, ATTACKER, VICTIM
    if not Path(path).exists():
        sys.exit(f"no {path}. Copy cakeshop/replay_config.json and adapt it for this app.")
    CFG = json.loads(Path(path).read_text())
    by_role = {}
    for u in CFG["users"]:
        USERS[u["name"]] = (u["username"], u["password"])
        by_role.setdefault(u.get("role", "user"), []).append(u["name"])
    ADMIN = (by_role.get("admin") or [None])[0]
    ATTACKER = (by_role.get("attacker") or by_role.get("user") or [None])[0]
    victims = by_role.get("victim") or [n for n in by_role.get("user", []) if n != ATTACKER]
    VICTIM = (victims or [None])[0]


def load(spec):
    """'module:function' -> the function."""
    mod, name = spec.split(":")
    return getattr(__import__(mod, fromlist=[name]), name)


def fresh_app():
    """A new app on a new database, seeded by the app's own init function, so no test sees another's effects."""
    state = tempfile.mkdtemp(dir=RUN_DIR)
    config = dict(CFG.get("test_config", {}))
    if CFG.get("db_config_key"):
        config[CFG["db_config_key"]] = os.path.join(state, "app.sqlite")
    for key in CFG.get("writable_dir_keys", []):
        config[key] = os.path.join(state, key.lower())
        os.makedirs(config[key])
    app = load(CFG["app"])(config)
    with app.app_context():
        load(CFG["init"])()
    return app


def login_fields():
    lg = CFG["login"]
    return lg.get("username_field", "username"), lg.get("password_field", "password")


class LoginFailed(Exception):
    pass


def tag_attr(tag, name):
    m = re.search(rf"\b{name}\s*=\s*([\"'])(.*?)\1", tag, re.I | re.S)
    return html.unescape(m.group(2)) if m else None


def hidden_fields(resp):
    """The hidden fields of an HTML page (typically a CSRF token), which a browser sends back with a form."""
    if "html" not in (resp.content_type or ""):
        return {}
    out = {}
    for tag in INPUT_TAG.findall(resp.get_data(as_text=True)):
        name = tag_attr(tag, "name")
        if (tag_attr(tag, "type") or "").lower() == "hidden" and name:
            out[name] = tag_attr(tag, "value") or ""
    return out


def page_tokens(client):
    """Hidden fields the app's login page gives this session, as a browser that loaded a page would have."""
    try:
        return hidden_fields(client.get(CFG["login"]["url"], follow_redirects=True))
    except Exception:
        return {}


def login_failed(resp):
    """True if the login was refused (an error, a redirect back to /login, or a page still asking for a password)."""
    if resp.status_code >= 400:
        return True
    if resp.status_code in REDIRECT:
        target = urlsplit(resp.headers.get("Location", "")).path.rstrip("/")
        return target == CFG["login"]["url"].rstrip("/")
    return bool(PASSWORD_BOX.search(resp.get_data(as_text=True)))


def login(app, creds):
    """A test client (a browser inside Python) logged in as (username, password), or anonymous for None."""
    client = app.test_client()
    if creds:
        user_field, pass_field = login_fields()
        data = dict(page_tokens(client))
        data.update({user_field: creds[0], pass_field: creds[1]})
        resp = client.open(CFG["login"]["url"], method=CFG["login"].get("method", "POST"), data=data)
        if login_failed(resp):
            raise LoginFailed(f"login as {creds[0]!r} was refused ({outcome(resp)}); "
                              f"check 'login' and 'users' in replay_config.json")
    client.form_tokens = page_tokens(client)
    return client


def db_file(app):
    raw = CFG.get("db_path") or str(app.config.get(CFG.get("db_config_key", ""), ""))
    return re.sub(r"^sqlite:(//)?/?", "", raw) or raw


def connect(app):
    con = sqlite3.connect(db_file(app))
    con.row_factory = sqlite3.Row
    return con


def snapshot(app):
    """Every row of every table (configured DB plus any sqlite file beside the app), to detect what a request changed."""
    paths = {db_file(app)} | {str(p) for ext in ("*.sqlite", "*.sqlite3", "*.db") for p in Path(".").glob(ext)}
    state = {}
    for path in paths:
        con = sqlite3.connect(path)
        for (tbl,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
            state[tbl] = sorted(map(repr, con.execute(f"SELECT * FROM {tbl}").fetchall()))
        con.close()
    return state


def user_id(con, name):
    pk = CFG.get("user_pk", "id")
    row = con.execute(f"SELECT {pk} FROM {CFG.get('users_table', 'users')} "
                      f"WHERE {CFG.get('username_column', 'username')} = ?", (USERS[name][0],)).fetchone()
    return row[pk] if row else None


def victim_data(app):
    """Strings stored in rows the victim owns; if one reaches a caller who should be blocked, data has leaked."""
    con = connect(app)
    victim = {user_id(con, VICTIM), USERS[VICTIM][0]}
    values = set()
    for (tbl,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
        cols = [r[1] for r in con.execute(f"PRAGMA table_info({tbl})")]
        owners = [c for c in cols if c.lower() in OWNER_COLS]
        for row in con.execute(f"SELECT * FROM {tbl}").fetchall():
            if any(row[c] in victim for c in owners):
                values |= {row[c] for c in cols if isinstance(row[c], str) and len(row[c]) > 4
                           and c.lower() not in OWNER_COLS}
    return values


def owner_col(card, tbl):
    """The column of `tbl` that says which user owns a row, if any."""
    return next((c for c in card["tables"].get(tbl) or [] if c.lower() in OWNER_COLS), None)


def owner_tables(card):
    """(table, owner column, file, line) for every table the route uses that stores who owns a row."""
    for s in card["sql"]:
        tbl = (s["table"] or "").strip("{}").lower()
        if owner_col(card, tbl):
            yield tbl, owner_col(card, tbl), s.get("file", card["file"]), s["line"]


def written_table(card):
    s = next((s for s in card["sql"] if s["verb"] in ("UPDATE", "INSERT") and s["table"]), None)
    return s["table"].strip("{}").lower() if s else None


def own_record_id(app, card, name):
    """An id of a record owned by `name`, so the request gets past an ownership check to the code behind it."""
    pk = CFG.get("record_pk", "id")
    con = connect(app)
    for tbl, owner, _, _ in owner_tables(card):
        row = con.execute(f"SELECT {pk} FROM {tbl} WHERE {owner} = ? LIMIT 1", (user_id(con, name),)).fetchone()
        if row:
            return row[pk]
    return None


def gate_level(card):
    """The access level the route really enforces, read from the checks inside its decorators, not their names."""
    conds = [c.get("if", "").lower() for d in card["decorators"] for c in d.get("checks", [])]
    if any(w in cond for cond in conds for w in ADMIN_WORDS):
        return "admin"
    if card["identity"] or any(("user" in c and "none" in c) or "authenticated" in c or "current_user" in c
                               or LOGIN_CHECK.search(c) for c in conds):
        return "logged_in_user"
    return "anyone"


def actor_for(card):
    """A caller who passes the route's real access check: (name, credentials)."""
    level = gate_level(card)
    if level == "admin":
        return ADMIN, USERS.get(ADMIN)
    if level == "logged_in_user":
        return ATTACKER, USERS.get(ATTACKER)
    return "anon", None


def route_src(idx, card):
    """Source of the route and the functions it calls, to see which sink a value reaches."""
    funcs = [(card["file"], card["function"])] + [(c["where"].split(":")[0], c["name"].split(" > ")[-1])
                                                  for c in card["calls"]]
    parts = []
    for rel, name in funcs:
        for node in ast.walk(idx.trees.get(rel) or ast.Module(body=[])):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                parts.append("\n".join(idx.files[rel][node.lineno - 1:node.end_lineno]))
                break
    return "\n".join(p for p in parts if p)


def defaults(card, part):
    """Harmless values for every field the route reads from `part` ("form" or "args")."""
    return {i["key"]: "1" if part == "form" and i.get("as") in ("int", "float", "Decimal") else "x" for i in card["inputs"]
            if i["part"] == part and i["key"] not in ("*", "?")}


def url_of(card, values=None, default=1):
    """The route's URL with its <params> filled in."""
    return re.sub(r"<(?:\w+:)?(\w+)>", lambda m: str((values or {}).get(m.group(1), default)), card["url"])


def pick_method(card, write):
    if write:
        for m in WRITE_METHODS:
            if m in card["methods"]:
                return m
    return "GET" if "GET" in card["methods"] else card["methods"][0]


def state_changing(card):
    return any(m in card["methods"] for m in WRITE_METHODS) or \
        any(s["verb"] in ("INSERT", "UPDATE", "DELETE", "REPLACE") for s in card["sql"])


def send(client, method, url, data=None, query=None, cookies=None, headers=None, tokens=True):
    """One request. With tokens=True the session's hidden form fields (see login) are added to the form."""
    if tokens and method != "GET" and getattr(client, "form_tokens", None):
        data = {**client.form_tokens, **(data or {})}
    for k, v in (cookies or {}).items():
        try:
            client.set_cookie(k, v)                 # werkzeug >= 2.3
        except TypeError:
            client.set_cookie("localhost", k, v)    # older werkzeug
    if query:
        url += ("&" if "?" in url else "?") + urlencode(query)
    return client.open(url, method=method, data=data if method != "GET" else None, headers=headers)


def outcome(resp):
    loc = resp.headers.get("Location", "") if resp.status_code in REDIRECT else ""
    return f"{resp.status_code}" + (f" -> {loc}" if loc else "")


def is_blocked(resp):
    if resp.status_code in (400, 401, 403, 404):
        return True
    return resp.status_code in REDIRECT and "/login" in resp.headers.get("Location", "")


def replay_access(app, card, level):
    """who_may_call: a caller below the required level opens the route."""
    if level not in ("logged_in_user", "admin"):
        return "not_applicable", "the route is public by its own rule", {}
    actor, creds = (ATTACKER, USERS.get(ATTACKER)) if level == "admin" else ("anon", None)
    method = pick_method(card, write=False)
    req = {"actor": actor, "method": method, "url": url_of(card), "need": level}
    resp = send(login(app, creds), method, req["url"], data=defaults(card, "form"),
                query=defaults(card, "args") or None)
    req["result"] = outcome(resp)
    if is_blocked(resp):
        return "dropped", f"{actor} is blocked ({outcome(resp)}) — the access check holds", req
    body = resp.get_data(as_text=True)
    leaked = sorted(v for v in victim_data(app) if v in body)
    if method == "GET" and resp.status_code == 200 and leaked:
        return "confirmed", f"{actor} (below '{level}') received {VICTIM}'s data {leaked[0]!r} — no access check", req
    return "dropped", f"{actor} not blocked ({outcome(resp)}) but saw no one's private data", req


def replay_ownership(app, card):
    """whose_data: the attacker opens a record owned by the victim."""
    target = next(owner_tables(card), None)
    if not card["url_params"] or not target:
        return "not_applicable", "no record id in the URL, or the table has no per-user owner column", {}
    tbl, owner, acc_file, acc_line = target
    con = connect(app)
    victim = con.execute(f"SELECT * FROM {tbl} WHERE {owner} = ? LIMIT 1", (user_id(con, VICTIM),)).fetchone()
    if victim is None:
        return "not_applicable", f"no {tbl} row owned by the victim to target", {}
    rid = victim["id"]
    method = pick_method(card, write=False)
    req = {"actor": ATTACKER, "method": method, "url": url_of(card, {card["url_params"][0]["name"]: rid}),
           "targets": f"{VICTIM}'s {tbl} #{rid}", "file": acc_file, "line": acc_line}
    before = dict(victim)
    resp = send(login(app, USERS[ATTACKER]), method, req["url"], data=defaults(card, "form"))
    req["result"] = outcome(resp)
    if is_blocked(resp):
        return "dropped", f"{ATTACKER} is blocked from {VICTIM}'s {tbl} #{rid} ({outcome(resp)}) — ownership checked", req
    after = connect(app).execute(f"SELECT * FROM {tbl} WHERE id = ?", (rid,)).fetchone()
    if after is None or dict(after) != before:      # a route that changes the record: did it change hers?
        what = "deleted" if after is None else \
            "changed " + ", ".join(k for k in before if before[k] != after[k])
        return "confirmed", f"{ATTACKER} {what} of {VICTIM}'s {tbl} #{rid} ({outcome(resp)})", req
    body = resp.get_data(as_text=True)
    leaked = [str(victim[k]) for k in victim.keys() if isinstance(victim[k], str) and len(victim[k]) > 4
              and k.lower() not in OWNER_COLS and victim[k] in body]
    if resp.status_code == 200 and leaked:
        return "confirmed", f"{ATTACKER} read {VICTIM}'s {tbl} #{rid}; response shows owner-only data {leaked[0]!r}", req
    return "dropped", f"{ATTACKER} got {outcome(resp)} but {VICTIM}'s data was not disclosed", req


def replay_value(app, card, rule_type, value, src):
    """limits / must_not_change / do_not_trust: send a rule-breaking value as a caller who passes the access check, on a record they own."""
    actor, creds = actor_for(card)
    me = actor if actor in USERS else ATTACKER
    my_id = own_record_id(app, card, me) or 1
    method = pick_method(card, state_changing(card))
    parts = {i["part"] for i in card["inputs"] if i["key"] in ("*", value)}
    in_url = any(p["name"] == value for p in card["url_params"])
    req = {"actor": actor, "method": method, "url": url_of(card, default=my_id), "value": value, "type": rule_type}

    def do(inject, cookies=None, login_as=None):
        """The request with `inject` as the value (in the form, the query string or the URL)."""
        form, query = defaults(card, "form"), defaults(card, "args")
        if login_as:                  # a login form: log in for real, with `inject` in the other field
            form.update(zip(login_fields(), login_as))
        if "form" in parts:
            form[value] = inject
        if "args" in parts:
            query[value] = inject
        url = url_of(card, {value: inject}, my_id) if in_url else req["url"]
        return send(login(app, creds), method, url, data=form, query=query or None, cookies=cookies)

    if rule_type == "do_not_trust":
        return replay_sink(app, card, value, src, do, req)
    if rule_type not in ("must_not_change", "limits"):
        return "uncertain", "unknown rule type", req

    tbl = written_table(card)
    if rule_type == "must_not_change":            # e.g. is_admin=1 on the user's own account
        resp = do("1")
        req["result"] = outcome(resp)
        if is_blocked(resp):
            return "dropped", f"the request was rejected ({outcome(resp)})", req
        cols = card["tables"].get(tbl) or []
        if value in cols:
            con = connect(app)
            lookup = "user_id" if "user_id" in cols else "id"
            rows = con.execute(f"SELECT {value} FROM {tbl} WHERE {lookup} = ?", (user_id(con, me),)).fetchall()
            if any(str(r[value]) == "1" for r in rows):
                return "confirmed", f"{me} set {tbl}.{value}=1 on their own row — privilege change", req
            return "dropped", f"{tbl}.{value} did not change — the field is protected", req
        return "uncertain", "request accepted but the effect could not be checked automatically", req

    resp = do("-5")                               # limits: an out-of-range value
    req["result"] = outcome(resp)
    if is_blocked(resp):
        return "dropped", f"the server rejected the out-of-range value -5 ({outcome(resp)})", req
    owner = owner_col(card, tbl)
    if owner:
        con = connect(app)
        row = con.execute(f"SELECT * FROM {tbl} WHERE {owner} = ? ORDER BY id DESC LIMIT 1",
                          (user_id(con, me),)).fetchone()
        if row:
            # the value's own column, or any number it fed into (total = price * quantity)
            bad = [f"{k}={row[k]}" for k in row.keys() if str(row[k]).lstrip("-").isdigit() and int(row[k]) < 0]
            if bad:
                return "confirmed", f"the server accepted {value}=-5 and stored {', '.join(bad)}", req
            return "dropped", "the out-of-range value was not stored", req
    return "uncertain", "value accepted but the stored effect could not be checked automatically", req


class MarkerFile:
    """Harmless pickle payload: unpickling it only creates one empty file."""
    def __init__(self, path):
        self.path = path

    def __reduce__(self):
        return open, (self.path, "w")


def replay_sink(app, card, value, src, do, req):
    """do_not_trust: a payload for the sink the value reaches, each proven by its own effect."""
    marker = os.path.join(tempfile.mkdtemp(dir=RUN_DIR), "MARKER")

    # open redirect: this value, read from the request, goes into redirect(...)
    if re.search(r"redirect\([^)]*request\.\w+(?:\.get\(|\[)\s*['\"]" + re.escape(value), src):
        evil = "http://replay.invalid/pwned"
        login_form = set(login_fields()) <= {i["key"] for i in card["inputs"] if i["part"] == "form"}
        resp = do(evil, login_as=USERS[VICTIM] if login_form else None)
        req["result"] = outcome(resp)
        loc = resp.headers.get("Location", "")
        if loc.startswith(evil):
            return "confirmed", f"the response redirects to the attacker URL {loc!r} — open redirect", req
        return "dropped", f"the value was not used as an external redirect ({outcome(resp)}, Location {loc!r})", req

    # command injection: a harmless payload that creates a marker file
    if "os.system" in src or ("subprocess" in src and "shell=True" in src):
        try:
            req["result"] = outcome(do(f"x; touch {marker}; echo"))
        except Exception as e:
            req["result"] = f"view raised {type(e).__name__} after the command ran"
        if os.path.exists(marker):
            return "confirmed", "a shell metacharacter payload ran a command (wrote a marker file) — command injection", req
        return "dropped", f"the payload did not run a command ({req['result']})", req

    # path traversal: ask for one of the app's own source files
    if "send_file" in src or "send_from_directory" in src or "os.path.join" in src:
        src_file = os.path.abspath(card["file"])
        base = next((app.config[k] for k in CFG.get("file_base_keys", []) if app.config.get(k)), app.root_path)
        rel = os.path.relpath(src_file, base)
        token = next((l.strip() for l in Path(src_file).read_text().splitlines() if len(l.strip()) > 15), "def ")
        resp = do(rel)
        req["result"] = outcome(resp)
        if resp.status_code == 200 and token in resp.get_data(as_text=True):
            return "confirmed", f"reading {rel!r} returned source code ({token!r}) — path traversal", req
        return "dropped", f"traversal to {rel!r} did not return the file ({outcome(resp)}) — path is sanitised", req

    # unsafe deserialisation: a pickled object in the cookie that creates a marker file
    in_cookie = any(i["part"] == "cookies" and i["key"] == value for i in card["inputs"])
    if in_cookie and ("pickle.loads" in src or "yaml.load" in src or "marshal.loads" in src):
        payload = base64.b64encode(pickle.dumps(MarkerFile(marker))).decode()
        try:                          # the view often crashes after the payload ran
            req["result"] = outcome(do("", cookies={value: payload}))
        except Exception as e:
            req["result"] = f"view raised {type(e).__name__} after the payload ran"
        if os.path.exists(marker):
            return "confirmed", "a crafted object in the cookie ran code (wrote a marker file) on deserialisation — RCE", req
        return "dropped", f"the crafted payload did not execute ({req['result']})", req

    # template injection: the value is concatenated into the template source
    if "render_template_string" in src and (re.search(r"[\"']\s*\+\s*" + re.escape(value), src)
                                            or re.search(value + r"\s*\+", src)):
        resp = do("{{7*7}}")
        req["result"] = outcome(resp)
        if "49" in resp.get_data(as_text=True):
            return "confirmed", "the expression {{7*7}} rendered as 49 — template injection", req
        return "dropped", "the expression was not evaluated — not injectable", req

    return "uncertain", "the value reaches a sink this replay does not model; keep for a human", req


def replay_csrf(app, card):
    """csrf: forge the state-changing request as another site would (no token, no custom headers); vulnerable if it still changed something."""
    actor, creds = actor_for(card)
    method = pick_method(card, write=True)
    form = defaults(card, "form")
    if set(login_fields()) <= set(form):
        form.update(zip(login_fields(), USERS[VICTIM]))
    if any(i["part"] == "form" and i["key"] == "*" for i in card["inputs"]):    # the route takes any field
        form.update({c: "x" for c in card["tables"].get(written_table(card)) or []
                     if c != "id" and c.lower() not in OWNER_COLS})
    client = login(app, creds)
    before = snapshot(app)
    resp = send(client, method, url_of(card), data=form, tokens=False,     # another site has no token
                query=defaults(card, "args") or None, headers={"Origin": "http://attacker.invalid"})
    changed = [f"table {t}" for t, rows in snapshot(app).items() if before.get(t) != rows]
    # A cookie other than the session cookie (a cart, a custom login cookie) is a real change. The session
    # cookie alone is not proof: apps rewrite it for flash messages and tokens, even on a refused request.
    session_cookie = app.config.get("SESSION_COOKIE_NAME", "session")
    set_names = {c.split("=", 1)[0].strip() for c in resp.headers.getlist("Set-Cookie")}
    if set_names - {session_cookie}:
        changed.append("cookies " + ", ".join(sorted(set_names - {session_cookie})))
    req = {"actor": actor, "method": method, "url": url_of(card), "result": outcome(resp), "changed": changed}
    if changed:
        return "confirmed", f"a forged {method} with no token changed {', '.join(changed)} ({outcome(resp)})", req
    if set_names:
        return "uncertain", (f"the forged {method} only rewrote the session cookie ({outcome(resp)}): a real "
                             f"change (log in/out) or bookkeeping (a flash message, a token); keep for a human"), req
    return "dropped", f"the forged {method} changed nothing ({outcome(resp)})", req


def replay(idx, card, rule_type, rule_text, level):
    app = fresh_app()
    if rule_type == "who_may_call":
        return replay_access(app, card, level)
    if rule_type == "whose_data":
        return replay_ownership(app, card)
    if rule_type in ("limits", "must_not_change", "do_not_trust"):
        return replay_value(app, card, rule_type, rule_text.split(":", 1)[0].strip(), route_src(idx, card))
    if rule_type == "csrf":
        return replay_csrf(app, card)
    return "uncertain", "no replay for this rule type", {}


def main():
    global RUN_DIR
    load_config()
    RUN_DIR = tempfile.mkdtemp(prefix="replay_")
    for name, creds in USERS.items():           # every test depends on the logins: check them first
        try:
            login(fresh_app(), creds)
        except LoginFailed as e:
            shutil.rmtree(RUN_DIR, ignore_errors=True)
            sys.exit(f"replay stopped: {e}")
    idx = CodeIndex(".")
    cards = {card["id"]: card for _, card in rc.all_cards(idx)}
    rules = {e["id"]: e for e in json.loads(Path("runs/rules.json").read_text())}

    jobs = [(f["extra"]["route"], f["rule_id"], f["extra"]["rule"], f)
            for f in json.loads(Path("runs/enforce.json").read_text())]
    # every whose_data rule is replayed, also the ones enforce.py accepted: a wrong "enforced" is caught here
    done = {job[:3] for job in jobs}
    jobs += [(rid, "whose_data", r["rule"], None) for rid, e in rules.items() for r in e["rules"]
             if r["type"] == "whose_data" and (rid, "whose_data", r["rule"]) not in done]

    kept, log = [], []
    for route, rule_type, rule_text, finding in jobs:
        card = cards.get(route)
        if card is None:
            continue
        level = rules.get(route, {}).get("decisions", {}).get("who_may_call") \
            or ("admin" if "administ" in rule_text.lower() else "logged_in_user")
        try:
            verdict, why, req = replay(idx, card, rule_type, rule_text, level)
        except Exception as e:
            verdict, why, req = "error", f"{type(e).__name__}: {e}", {}
        entry = {"route": route, "rule_type": rule_type, "rule": rule_text,
                 "from_finding": finding is not None, "verdict": verdict, "why": why, "request": req}
        log.append(entry)
        if verdict in ("confirmed", "uncertain"):
            if finding is None:       # a whose_data rule enforce.py had accepted
                rel, line = req.get("file", card["file"]), req.get("line", card["lines"][0])
                finding = {"tool": "replay", "rule_id": rule_type, "title": f"Rule not enforced: {rule_text}",
                           "file": rel, "line": line, "snippet": idx.line(rel, line).strip(),
                           "cwe": ["CWE-639"], "extra": {"route": route, "rule": rule_text}}
            kept.append(dict(finding, confidence=verdict, extra=dict(finding["extra"], replay=entry)))
        print(f"  {route:<42} {rule_type:<16} {verdict:<13} {why[:62]}" + ("" if entry["from_finding"] else "  (re-check)"))

    shutil.rmtree(RUN_DIR, ignore_errors=True)
    Path("runs/replay.json").write_text(json.dumps(kept, indent=2))
    Path("runs/replay_log.json").write_text(json.dumps(log, indent=2))
    count = lambda *vs: sum(e["verdict"] in vs for e in log)
    print(f"\n{len(jobs)} rules replayed: {count('confirmed')} confirmed, {count('dropped')} dropped, "
          f"{count('uncertain', 'error')} kept or failed -> runs/replay.json")


if __name__ == "__main__":
    main()
