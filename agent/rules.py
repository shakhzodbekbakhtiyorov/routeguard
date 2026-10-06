"""The rules each route must follow, as 4 questions based on OWASP. The model says what a route SHOULD"""
import ast
import json
import time
from pathlib import Path

import llm
import routecard as rc
from codeindex import CodeIndex, span

NUM_CTX = 4096
ANSWER_TOKENS = 800
MAX_USE_LINES = 8

INTENT_NOTE = """Judge from what the route is FOR: its URL, the data it reads or writes, the page it shows.
Do not base your answer on decorators or checks in the code; whether they are right is tested later."""

ROUTE_SYSTEM = f"""You are a security reviewer for a web application. You are given ONE route (an HTTP endpoint).
Answer two questions about what this route SHOULD guarantee if the application is correct.
{INTENT_NOTE}

1. who_may_call (OWASP: broken access control / function level authorization):
   who should be allowed to use this route at all?
   "anyone" = public, "logged_in_user" = any signed-in user, "admin" = administrators only.
2. whose_data (OWASP: broken object level authorization / IDOR):
   does the route read or change a record that belongs to one particular user account, i.e. the
   table stores who owns the row (a user id or username column)? Public data such as a product
   catalogue, and data kept only in the visitor's own browser, do not count.
   If yes, name the table and write the rule as one full sentence.

For each answer give the reason first: one sentence about this route's purpose and data.
Reply with JSON only."""

ROUTE_SCHEMA = {"type": "object", "properties": {
    "who_may_call": {"type": "object", "properties": {
        "reason": {"type": "string"},
        "answer": {"type": "string", "enum": ["anyone", "logged_in_user", "admin"]}},
        "required": ["reason", "answer"]},
    "whose_data": {"type": "object", "properties": {
        "reason": {"type": "string"}, "applies": {"type": "boolean"},
        "table": {"type": "string"}, "rule": {"type": "string"}},
        "required": ["reason", "applies", "table", "rule"]}},
    "required": ["who_may_call", "whose_data"]}

CATEGORIES = {
    "content": "ordinary content the user is free to choose (a name, a message, a search text, a password "
               "they set)",
    "selects_record": "an id or key that picks which record to read or change",
    "server_decides": "a value the server must decide, look up or check itself, because a wrong or "
                      "malicious value causes harm (an amount or price, a redirect target, a file path, "
                      "serialized data, someone's identity)",
    "needs_limits": "a number or a choice that must stay within bounds or within a fixed set of values "
                    "(a count, a status)",
    "must_not_set": "a stored field the client must not be able to set at all through this route "
                    "(a role or permission, an owner id)",
}

VALUE_SYSTEM = f"""You are a security reviewer for a web application. You are given ONE route and every value
the client sends to it, with the lines where each value is used.
For EACH value, decide what kind of value it is, judging from what it means and where it ends up.
{INTENT_NOTE}

Kinds (OWASP: mass assignment / object property level authorization, and insecure design):
""" + "\n".join(f"- {k}: {v}" for k, v in CATEGORIES.items()) + """

For each value give, in this order:
- reason: one sentence on what the value is and where it ends up
- kind: one of the kinds above
- rule: if the kind is server_decides, needs_limits or must_not_set, one full sentence that names the value
  and says what the server must do; otherwise an empty string
Reply with JSON only."""

RULE_TYPE = {"server_decides": "do_not_trust", "needs_limits": "limits", "must_not_set": "must_not_change"}


def code_bundle(idx, route, card):
    """Raw code of everything that runs for a route: route, decorators, constants, helpers, hook, templates, tables."""
    rel, func = route["file"], route["node"]
    sections = [("ROUTE", rel, idx.source(rel, func, max_lines=80))]
    for d in func.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", None)
        if name in rc.ROUTE_DECORATORS:
            continue
        hit = rc.resolve(idx, rel, name) if name else None
        if hit and isinstance(hit[1], (ast.FunctionDef, ast.AsyncFunctionDef)):
            sections.append((f"DECORATOR {name}", hit[0], idx.source(hit[0], hit[1])))
            for inner in ast.walk(hit[1]):          # a decorator built on another one
                if isinstance(inner, ast.FunctionDef):
                    for x in inner.decorator_list:
                        n = getattr(x, "id", None)
                        h2 = rc.resolve(idx, hit[0], n) if n else None
                        if h2 and all(s[0] != f"DECORATOR {n}" for s in sections):
                            sections.append((f"DECORATOR {n}", h2[0], idx.source(h2[0], h2[1])))
    for name in card["constants"]:
        hit = rc.resolve(idx, rel, name)
        if hit:
            sections.append((f"CONSTANT {name}", hit[0], idx.numbered(hit[0], *span(hit[1]))))
    for c in card["calls"]:
        name = c["name"].split(" > ")[-1]
        hit = rc.resolve(idx, c["where"].split(":")[0], name)
        if hit:
            sections.append((f"CALLED {name}", hit[0], idx.source(hit[0], hit[1])))
    for h in card["app_hooks"]:
        hrel, line = h["where"].rsplit(":", 1)
        node = idx.enclosing_function(hrel, int(line) + 1)
        if node:
            sections.append((f"RUNS BEFORE EVERY REQUEST {h['function']}", hrel, idx.source(hrel, node)))
    for t in card["templates"]:
        sections.append(("TEMPLATE", t, idx.numbered(t, 1, len(idx.files[t]))))
    tables = {t.lower() for t in card["tables"] if card["tables"][t]} | set(card["related_tables"])
    for tree in idx.trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for m in rc.CREATE_TABLE.finditer(node.value):
                    if m.group(1).lower() in tables:
                        sections.append(("TABLE", "schema", m.group(0).strip()))
    return sections


def route_prompt(idx, route, card, budget):
    """The raw code of everything that runs for the route; sections are dropped from the end until it fits the budget."""
    header = f"Route: {card['id']}  (function {card['function']} in {card['file']})"
    sections = code_bundle(idx, route, card)
    dropped = 0
    while True:
        code = "\n\n".join(f"--- {title} ({where}) ---\n{body}" for title, where, body in sections)
        text = f"{header}\n\nCODE:\n{code}"
        if len(text) <= budget or len(sections) == 1:
            break
        sections.pop()
        dropped += 1
    return text + (f"\n\n({dropped} code section(s) left out for space)" if dropped else "")


def stmt_lines(stmt):
    return stmt.lineno, getattr(stmt, "end_lineno", stmt.lineno) or stmt.lineno


def smallest_stmt(func, node):
    """The innermost statement that contains `node`."""
    best = None
    for st in ast.walk(func):
        if not isinstance(st, ast.stmt) or st is func:
            continue
        a, b = stmt_lines(st)
        if a <= node.lineno <= b and (best is None or (b - a) <= (stmt_lines(best)[1] - stmt_lines(best)[0])):
            if not isinstance(st, (ast.For, ast.If, ast.With, ast.While, ast.Try)) or st.lineno == node.lineno:
                best = st
    return best


def assigned_names(stmt):
    if isinstance(stmt, ast.Assign):
        targets = stmt.targets
    elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign, ast.For)):
        targets = [stmt.target]
    else:
        return set()
    return {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}


def value_uses(func, access_node):
    """Line ranges showing where a client value goes: the line that reads it, then (two steps deep)"""
    first = smallest_stmt(func, access_node)
    if first is None:
        return []
    a, b = stmt_lines(first)
    ranges = [(a, b)] if b - a <= 2 else [(a, a + 1), (access_node.lineno, access_node.lineno)]
    if isinstance(first, ast.For):              # for key, value in request.form.items()
        ranges = [(first.lineno, first.lineno)]
    names, seen = assigned_names(first), {first}
    for _ in range(2):
        new = set()
        for node in ast.walk(func):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in names:
                st = smallest_stmt(func, node)
                if st is not None and st not in seen:
                    seen.add(st)
                    a, b = stmt_lines(st)
                    ranges += [(a, b)] if b - a <= 2 else [(a, a + 1), (node.lineno, node.lineno)]
                    new |= assigned_names(st)
        names = new
        if not names:
            break
    out = []
    for a, b in sorted(set(ranges)):
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(b, out[-1][1]))
        else:
            out.append((a, b))
    return out


def client_values(idx, route, card):
    """Every value the client sends: name, how it is read, and the lines that use it. A loop over ALL"""
    rel, func = route["file"], route["node"]
    values, seen = [], set()
    for p in card["url_params"]:
        values.append({"name": p["name"], "how": f"URL parameter <{p['type']}:{p['name']}>", "file": rel,
                       "lines": [(func.lineno, func.lineno)]})
    for inp in card["inputs"]:
        key = (inp["part"], inp["key"], inp["via"])
        if key in seen:
            continue
        seen.add(key)
        where_rel, where_func = rel, func
        if inp["via"]:
            hit = rc.resolve(idx, rel, inp["via"].split(" > ")[-1])
            if not hit:
                continue
            where_rel, where_func = hit
        node = next((n for n in ast.walk(where_func) if rc.request_access(n) == (inp["part"], inp["key"])), None)
        lines = value_uses(where_func, node) if node is not None else [(inp["line"], inp["line"])]
        how = f"request.{inp['part']}" + ("" if inp["key"] == "*" else f"[{inp['key']!r}]")
        how += f", converted with {inp['as']}()" if inp["as"] else ""
        how += f", read inside {inp['via']}()" if inp["via"] else ""
        if inp["key"] == "*":
            written = [s for s in card["sql"] if s["verb"] in ("UPDATE", "INSERT") and s["table"]]
            table = written[0]["table"].lower() if written else None
            cols = [c for c in (card["tables"].get(table) or []) if c != "id"] if table else []
            for col in cols or ["(any field name)"]:
                values.append({"name": col, "how": f"any form field name ({how}); here: a field named {col!r} "
                               f"that would be written to {table}.{col}", "file": where_rel, "lines": lines})
        else:
            values.append({"name": inp["key"], "how": how, "file": where_rel, "lines": lines})
    counts = {}                  # names are JSON keys in the answer, so make them unique
    for v in values:
        counts[v["name"]] = counts.get(v["name"], 0) + 1
        if counts[v["name"]] > 1:
            v["name"] = f"{v['name']}_{counts[v['name']]}"
    return values


def render_values(idx, values):
    out = []
    for v in values:
        out.append(f"VALUE {v['name']}: {v['how']}")
        shown, last = 0, None
        for a, b in v["lines"]:
            if shown >= MAX_USE_LINES:
                out.append("        ...")
                break
            if last is not None and a > last + 1:
                out.append("        ...")
            b = min(b, a + MAX_USE_LINES - shown - 1)
            out.append(idx.numbered(v["file"], a, b))
            shown, last = shown + b - a + 1, b
        out.append("")
    return "\n".join(out)


def value_schema(values):
    item = {"type": "object", "properties": {
        "reason": {"type": "string"}, "kind": {"type": "string", "enum": list(CATEGORIES)},
        "rule": {"type": "string"}}, "required": ["reason", "kind", "rule"]}
    return {"type": "object", "properties": {v["name"]: item for v in values}, "required": [v["name"] for v in values]}


def changes_state(idx, route, card):
    """Q3, decided by code: a non-GET method, a write to the database, or a change to the session."""
    why = []
    if any(m in ("POST", "PUT", "PATCH", "DELETE") for m in card["methods"]):
        why.append("method " + "/".join(card["methods"]))
    writes = [s for s in card["sql"] if s["verb"] in ("INSERT", "UPDATE", "DELETE", "REPLACE")]
    if writes:
        why.append(f"{writes[0]['verb']} {writes[0]['table']}")
    funcs = [route["node"]] + [h[1] for c in card["calls"]
                               for h in [rc.resolve(idx, c["where"].split(":")[0], c["name"].split(" > ")[-1])] if h]
    for fn in funcs:
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                    getattr(n.func.value, "id", None) == "session" and n.func.attr in ("clear", "pop", "update"):
                why.append(f"session.{n.func.attr}()")
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Subscript) and getattr(t.value, "id", None) == "session"
                                                 for t in n.targets):
                why.append("writes the session")
    return bool(why), sorted(set(why))


def ask(system, prompt, schema):
    t0 = time.time()
    try:
        answer = llm.ask(system, prompt, schema, NUM_CTX, max_tokens=ANSWER_TOKENS)
    except llm.LLMError as e:
        answer = {"error": str(e)}
    return answer, round(time.time() - t0, 1)


def rules_for(idx, route, card, entry):
    """Ask Q1-Q4 for one route. Returns (rules, decisions); prompts and answers go into `entry`."""
    rules, decisions = [], {}

    # Q1 + Q2
    prompt = route_prompt(idx, route, card, llm.code_budget(NUM_CTX, ANSWER_TOKENS, ROUTE_SYSTEM))
    ans, secs = ask(ROUTE_SYSTEM, prompt, ROUTE_SCHEMA)
    entry.update(route_prompt=prompt, route_answer=ans, route_seconds=secs)
    who = ans.get("who_may_call") or {}
    decisions["who_may_call"] = who.get("answer")
    if who.get("answer") in ("logged_in_user", "admin"):
        label = "administrators" if who["answer"] == "admin" else "logged-in users"
        rules.append({"type": "who_may_call", "applies_because": who.get("reason", ""),
                      "rule": f"Only {label} may call {card['url']}."})
    wd = ans.get("whose_data") or {}
    decisions["whose_data"] = wd.get("applies")
    if wd.get("applies") is True:
        rules.append({"type": "whose_data", "applies_because": wd.get("reason", ""),
                      "rule": wd.get("rule") or f"Only the owner may reach their {wd.get('table')} records."})

    # Q3
    state, why = changes_state(idx, route, card)
    decisions["csrf"] = state
    if state:
        rules.append({"type": "csrf", "applies_because": "changes state: " + ", ".join(why),
                      "rule": f"{'/'.join(card['methods'])} {card['url']} changes state, so a request forged "
                              f"from another website must be rejected (CSRF token)."})

    # Q4
    values = client_values(idx, route, card)
    if values:
        prompt = (f"Route: {card['id']}  (function {card['function']} in {card['file']})\n\n"
                  f"ROUTE CODE:\n{idx.source(route['file'], route['node'], max_lines=40)}\n\n"
                  f"VALUES SENT BY THE CLIENT:\n{render_values(idx, values)}")
        vans, vsecs = ask(VALUE_SYSTEM, prompt, value_schema(values))
        entry.update(value_prompt=prompt, value_answer=vans, value_seconds=vsecs)
        decisions["values"] = {}
        for v in values:
            d = vans.get(v["name"]) or {}
            decisions["values"][v["name"]] = d.get("kind")
            if d.get("kind") in RULE_TYPE:
                rules.append({"type": RULE_TYPE[d["kind"]], "applies_because": d.get("reason", ""),
                              "rule": f"{v['name']}: {d.get('rule') or CATEGORIES[d['kind']]}"})
    return rules, decisions


def main():
    idx = CodeIndex(".")
    llm.check_ollama()
    results, log, t0 = [], [], time.time()
    for route, card in rc.all_cards(idx):
        entry = {"id": card["id"], "url": card["url"]}
        log.append(entry)
        rules, decisions = rules_for(idx, route, card, entry)
        error = entry["route_answer"].get("error") or entry.get("value_answer", {}).get("error")
        results.append({"id": card["id"], "url": card["url"], "methods": card["methods"], "rules": rules,
                        "decisions": decisions, "error": error})
        values = decisions.get("values") or {}
        print(f"  {card['id']:<45} who={decisions['who_may_call']}, own={decisions['whose_data']}, "
              f"csrf={decisions['csrf']}" + (f", values: {', '.join(f'{k}={v}' for k, v in values.items())}" if values else "")
              + ("  ERROR" if error else ""))
    Path("runs").mkdir(exist_ok=True)
    Path("runs/rules.json").write_text(json.dumps(results, indent=2))
    Path("runs/rules_log.json").write_text(json.dumps(log, indent=2))
    print(f"\n{sum(len(r['rules']) for r in results)} rules for {len(results)} routes -> runs/rules.json   "
          f"{time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
