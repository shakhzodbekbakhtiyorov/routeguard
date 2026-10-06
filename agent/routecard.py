"""Route cards: the facts about every Flask route that can be read from the code (no model)."""
import ast
import json
import re
import sys
from pathlib import Path

from codeindex import CodeIndex, call_name, span

ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete"}
REQUEST_PARTS = {"args", "form", "values", "cookies", "headers", "json", "files", "data", "view_args"}
FOLLOW_DEPTH = 2        # how deep to follow calls into project functions

SQL_START = re.compile(r"^\s*(SELECT|INSERT|UPDATE|DELETE|REPLACE)\b", re.I)
CREATE_TABLE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?(\w+)[`\"]?\s*\((.*?)\)\s*;", re.I | re.S)


def short(text, limit=140):
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[:limit - 3] + "..."


def find_schema(idx):
    """Table -> columns, from CREATE TABLE statements in the project's strings."""
    tables = {}
    for tree in idx.trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "CREATE" in node.value.upper():
                for name, body in CREATE_TABLE.findall(node.value):
                    cols = []
                    for part in body.split(","):
                        word = part.strip().split()[0].strip('`"') if part.strip() else ""
                        if word and word.upper() not in {"PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"} \
                                and not word.startswith("("):
                            cols.append(word)
                    tables[name.lower()] = cols
    return tables


def sql_text(node):
    """The SQL in a string, f-string or "..." + x, with dynamic parts shown as {expr}."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        text = node.value
    elif isinstance(node, ast.JoinedStr):
        text = "".join(v.value if isinstance(v, ast.Constant) else "{" + ast.unparse(v.value) + "}" for v in node.values)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = sql_text(node.left), sql_text(node.right)
        text = (left or "{" + ast.unparse(node.left) + "}") + (right or "{" + ast.unparse(node.right) + "}")
    else:
        return None
    return text if SQL_START.match(text) else None


def parse_sql(text):
    """Verb, table, joined tables and the columns written. Rough, but enough here."""
    t = re.sub(r"\s+", " ", text).strip()
    verb = t.split()[0].upper()
    table, written = None, []
    if verb in ("SELECT", "DELETE"):
        m = re.search(r"\bFROM\s+(\{?[\w.]+\}?)" if verb == "SELECT" else r"\bFROM\s+(\{?\w+\}?)", t, re.I)
        table = m and m.group(1)
    elif verb in ("INSERT", "REPLACE"):
        m = re.search(r"\bINTO\s+(\{?\w+\}?)\s*\(([^)]*)\)", t, re.I)
        if m:
            table, written = m.group(1), [c.strip() for c in m.group(2).split(",")]
        else:
            m = re.search(r"\bINTO\s+(\{?\w+\}?)", t, re.I)
            table = m and m.group(1)
    elif verb == "UPDATE":
        m = re.search(r"^UPDATE\s+(\{?\w+\}?)\s+SET\s+(.*?)(?:\bWHERE\b|$)", t, re.I)
        if m:
            table = m.group(1)
            written = [a.split("=")[0].strip() for a in m.group(2).split(",") if "=" in a]
    return {"verb": verb, "table": table, "joins": re.findall(r"\bJOIN\s+(\w+)", t, re.I), "writes": written}


def request_access(node):
    """('form', 'price') for request.form["price"] or .get("price"); ('form', '*') for request.form.items();"""
    def part_of(n):
        return n.attr if (isinstance(n, ast.Attribute) and n.attr in REQUEST_PARTS
                          and isinstance(n.value, ast.Name) and n.value.id == "request") else None

    if isinstance(node, ast.Subscript) and part_of(node.value):
        key = node.slice.value if isinstance(node.slice, ast.Constant) else ast.unparse(node.slice)
        return part_of(node.value), key
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        part = part_of(node.func.value)
        if part and node.func.attr in ("get", "getlist"):
            key = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else "?"
            return part, key
        if part and node.func.attr in ("items", "keys", "values", "to_dict", "copy", "lists"):
            return part, "*"
        if isinstance(node.func.value, ast.Name) and node.func.value.id == "request" and node.func.attr == "get_json":
            return "json", "*"
    if isinstance(node, ast.Attribute) and node.attr in ("json", "data") and \
            isinstance(node.value, ast.Name) and node.value.id == "request":
        return node.attr, "*"
    return None


NUMBER_TYPES = ("int", "float", "bool", "Decimal")


def converted(parents, node):
    """int(request.form["n"]) or request.form.get("n", type=int) -> "int"."""
    p = parents.get(node)
    if isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and p.func.id in NUMBER_TYPES:
        return p.func.id
    if isinstance(node, ast.Call):
        for kw in node.keywords:
            if kw.arg == "type" and isinstance(kw.value, ast.Name) and kw.value.id in NUMBER_TYPES:
                return kw.value.id
    return None


def identity_use(node):
    """g.user[...], g.session[...], session[...], current_user.x or a comparison with g.user."""
    if isinstance(node, ast.Subscript):
        base = node.value
        if (isinstance(base, ast.Attribute) and base.attr in ("user", "session")
                and isinstance(base.value, ast.Name) and base.value.id == "g") \
                or (isinstance(base, ast.Name) and base.id == "session"):
            return ast.unparse(node)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "current_user":
        return ast.unparse(node)
    if isinstance(node, ast.Compare) and isinstance(node.left, ast.Attribute) and node.left.attr == "user" \
            and getattr(node.left.value, "id", None) == "g":
        return ast.unparse(node)
    return None


def what_happens(body):
    """The first statement of an if-branch: an exit (abort/redirect/raise/return) or the code that runs."""
    for stmt in body:
        if isinstance(stmt, ast.Raise):
            return "raise " + short(ast.unparse(stmt.exc) if stmt.exc else "", 60)
        if isinstance(stmt, ast.Return):
            return "return " + short(ast.unparse(stmt.value) if stmt.value else "", 60)
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and call_name(stmt.value) in ("abort", "redirect"):
            return short(ast.unparse(stmt.value), 60)
    return "then runs: " + short(ast.unparse(body[0]), 70) if body else "nothing"


def template_of(idx, call):
    """The template file of render_template('x.html', ...)."""
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return next((r for r in idx.files if r.endswith("templates/" + call.args[0].value)), None)
    return None


def read_function(idx, func):
    """Facts from one function body, without following calls."""
    parents = {child: parent for parent in ast.walk(func) for child in ast.iter_child_nodes(parent)}
    facts = {"inputs": [], "identity": [], "sql": [], "checks": [], "calls": [], "constants": [], "templates": []}
    seen_identity = set()
    for node in ast.walk(func):
        acc = request_access(node)
        if acc and not (isinstance(node, ast.Attribute) and isinstance(parents.get(node), (ast.Subscript, ast.Call))
                        and request_access(parents[node])):
            facts["inputs"].append({"part": acc[0], "key": acc[1], "line": node.lineno,
                                    "as": converted(parents, node)})
        who = identity_use(node)
        if who and (who, node.lineno) not in seen_identity:
            seen_identity.add((who, node.lineno))
            facts["identity"].append({"use": who, "line": node.lineno})
        text = sql_text(node)
        if text and not isinstance(parents.get(node), ast.JoinedStr) \
                and not (isinstance(parents.get(node), ast.BinOp) and sql_text(parents[node])):
            facts["sql"].append({"line": node.lineno, "text": short(text, 200), **parse_sql(text)})
        if isinstance(node, ast.If):
            facts["checks"].append({"line": node.lineno, "if": short(ast.unparse(node.test), 90),
                                    "then": what_happens(node.body)})
        if isinstance(node, ast.Call):
            name = call_name(node)
            if isinstance(node.func, ast.Name) and name in idx.defs:
                facts["calls"].append(name)
            if name == "render_template" and template_of(idx, node):
                facts["templates"].append(template_of(idx, node))
        if isinstance(node, ast.Name) and node.id.isupper() and node.id in idx.defs:
            facts["constants"].append(node.id)
    facts["calls"] = sorted(set(facts["calls"]) - {func.name})
    facts["constants"] = sorted(set(facts["constants"]))
    return facts


def resolve(idx, rel, name):
    """(file, node) of a project definition visible from `rel`."""
    hit = idx.visible_def(rel, name) if rel in idx.trees else None
    if hit is None and len(idx.defs.get(name, [])) == 1:
        hit = idx.defs[name][0]
    return hit


def follow_calls(idx, rel, facts, depth, seen):
    """Facts of the project functions a route calls: [(name, file, node, facts)]."""
    out = []
    for name in facts["calls"]:
        hit = resolve(idx, rel, name)
        if not hit or not isinstance(hit[1], (ast.FunctionDef, ast.AsyncFunctionDef)) or (hit[0], name) in seen:
            continue
        seen.add((hit[0], name))
        sub = read_function(idx, hit[1])
        out.append((name, hit[0], hit[1], sub))
        if depth > 1:
            out += [(f"{name} > {n}", r, nd, s) for n, r, nd, s in follow_calls(idx, hit[0], sub, depth - 1, seen)]
    return out


def decorator_info(idx, rel, func):
    """Non-route decorators; for project ones, the checks inside them and the decorators they wrap."""
    out = []
    for d in func.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", None)
        if name in ROUTE_DECORATORS:
            continue
        info = {"name": ast.unparse(d), "checks": []}
        hit = resolve(idx, rel, name) if name else None
        if hit and isinstance(hit[1], (ast.FunctionDef, ast.AsyncFunctionDef)):
            info["checks"] = read_function(idx, hit[1])["checks"]
            # a decorator built on another one (admin_required wraps login_required)
            info["uses"] = [ast.unparse(x) for n in ast.walk(hit[1]) if isinstance(n, ast.FunctionDef)
                            for x in n.decorator_list if not ast.unparse(x).startswith(("functools.wraps", "wraps"))]
        out.append(info)
    return out


def app_hooks(idx):
    """Functions that run before every request."""
    return [{"function": func.name, "where": f"{rel}:{func.lineno}"} for rel, func in idx.functions()
            if any(ast.unparse(d.func if isinstance(d, ast.Call) else d).endswith(("before_request", "before_app_request"))
                   for d in func.decorator_list)]


def blueprint_prefixes(idx):
    """(file, blueprint variable) -> url_prefix from Blueprint(...) or app.register_blueprint(...), by name (bp) or module (module.bp)."""
    registered = {}
    for tree in idx.trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "register_blueprint" and node.args:
                prefix = next((k.value.value for k in node.keywords
                               if k.arg == "url_prefix" and isinstance(k.value, ast.Constant)), None)
                bp = node.args[0]
                if prefix is None:
                    continue
                if isinstance(bp, ast.Name):                  # register_blueprint(bp, ...)
                    registered[(None, bp.id)] = prefix
                elif isinstance(bp, ast.Attribute) and isinstance(bp.value, ast.Name):
                    registered[(bp.value.id, bp.attr)] = prefix   # register_blueprint(module.bp, ...)
    prefixes = {}
    for rel, tree in idx.trees.items():
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and \
                    call_name(node.value) in ("Blueprint", "Flask"):
                own = next((k.value.value for k in node.value.keywords
                            if k.arg == "url_prefix" and isinstance(k.value, ast.Constant)), None)
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        module = Path(rel).stem if Path(rel).stem != "__init__" else Path(rel).parent.name
                        prefixes[(rel, t.id)] = own if own is not None else \
                            registered.get((module, t.id), registered.get((None, t.id), ""))
    return prefixes


def find_routes(idx):
    """Every view function (@x.route, and the @x.get / @x.post shortcuts); one entry per URL."""
    prefixes = blueprint_prefixes(idx)
    out = []
    for rel, func in idx.functions():
        for d in func.decorator_list:
            if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_DECORATORS
                    and d.args and isinstance(d.args[0], ast.Constant)):
                continue
            if d.func.attr == "route":
                methods = ["GET"]
                for kw in d.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        methods = [e.value.upper() for e in kw.value.elts if isinstance(e, ast.Constant)]
            else:
                methods = [d.func.attr.upper()]
            owner = d.func.value.id if isinstance(d.func.value, ast.Name) else None
            url = prefixes.get((rel, owner), "") + d.args[0].value
            out.append({"file": rel, "function": func.name, "node": func, "url": url, "methods": methods})
    return out


def build_card(idx, route, schema, hooks):
    rel, func = route["file"], route["node"]
    own = read_function(idx, func)
    card = {
        "id": f"{'/'.join(route['methods'])} {route['url']}",
        "url": route["url"], "methods": route["methods"], "function": func.name,
        "file": rel, "lines": list(span(func)),
        "url_params": [{"name": n, "type": t or "string"} for t, n in re.findall(r"<(?:(\w+):)?(\w+)>", route["url"])],
        "decorators": decorator_info(idx, rel, func),
        "inputs": [dict(i, via=None) for i in own["inputs"]],
        "identity": [dict(i, via=None) for i in own["identity"]],
        "sql": [dict(s, via=None, file=rel) for s in own["sql"]],
        "calls": [],
        "constants": set(own["constants"]),
        "templates": own["templates"],
    }
    for name, crel, cnode, sub in follow_calls(idx, rel, own, FOLLOW_DEPTH, {(rel, func.name)}):
        card["calls"].append({"name": name, "where": f"{crel}:{cnode.lineno}"})
        card["inputs"] += [dict(i, via=name) for i in sub["inputs"]]
        card["identity"] += [dict(i, via=name) for i in sub["identity"]]
        card["sql"] += [dict(s, via=name, file=crel) for s in sub["sql"]]
        card["constants"] |= set(sub["constants"])
    for key in ("inputs", "identity", "sql"):
        card[key].sort(key=lambda x: (x["via"] is not None, x["line"]))
    card["constants"] = [n for n in sorted(card["constants"])
                         if (hit := resolve(idx, rel, n)) and isinstance(hit[1], (ast.Assign, ast.AnnAssign))
                         and hit[1].value is not None]

    tables = {}
    for s in card["sql"]:
        for t in [s["table"]] + s["joins"]:
            if t and t.strip("{}").lower() in schema:
                tables[t.lower()] = schema[t.lower()]
            elif t:
                tables[t] = None      # dynamic ({table}) or not in the schema
    card["tables"] = tables
    # other tables with a column named like the route's data (the request sends `price`, `products` stores it)
    names = {i["key"] for i in card["inputs"] if i["key"] not in ("*", "?")} | {w for s in card["sql"] for w in s["writes"]}
    names -= {"id"}
    card["related_tables"] = [t for t, cols in schema.items() if t not in {x.lower() for x in tables} and names & set(cols)]
    card["app_hooks"] = hooks
    return card


def all_cards(idx):
    """[(route, card)] for every route in the project."""
    schema, hooks = find_schema(idx), app_hooks(idx)
    return [(r, build_card(idx, r, schema, hooks)) for r in find_routes(idx)]


def main():
    idx = CodeIndex(".")
    cards = [card for _, card in all_cards(idx)]
    if len(sys.argv) > 1:
        for c in cards:
            if c["url"] == sys.argv[1]:
                print(json.dumps(c, indent=2))
        return
    Path("runs").mkdir(exist_ok=True)
    Path("runs/routecards.json").write_text(json.dumps(cards, indent=2))
    print(f"{len(cards)} routes -> runs/routecards.json")

    # self-check: every request.* read in the project should be on some card
    on_cards = {(i["line"], i["part"]) for c in cards for i in c["inputs"]}
    for rel, tree in idx.trees.items():
        for node in ast.walk(tree):
            acc = request_access(node)
            if acc and (node.lineno, acc[0]) not in on_cards:
                print(f"  not on any card: {rel}:{node.lineno} request.{acc[0]} {acc[1]}")


if __name__ == "__main__":
    main()
