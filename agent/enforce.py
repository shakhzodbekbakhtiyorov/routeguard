"""For each rule from rules.py, which line enforces it? The model answers; code checks the copied line exists and runs for the route."""
import ast
import json
import re
from pathlib import Path

import llm
import routecard as rc
import rules as rl
from codeindex import CodeIndex, anchor, contains, norm, span

NUM_CTX = 4096
ANSWER_TOKENS = 600

SYSTEM = """You are a security reviewer for a web application. You are given ONE rule that a route
(an HTTP endpoint) must follow, and the code that runs when the route is called.
Does the code enforce the rule?

- enforced: a line in the code makes it impossible to break the rule. Copy that line into "code".
- not_enforced: no line does. A check that still lets a bad request through (a wrong allow-list entry,
  a check on the wrong field) does not count. Copy the line where the rule is broken into "code", and
  describe in "attack" one request that breaks it: who is logged in, method, URL, values, what happens.
- not_applicable: the rule does not fit this route.

Give "file" and "line" of the copied code, a short "reason", the "status", and a "cwe" for the problem
(empty unless not_enforced). Reply with JSON only."""

SCHEMA = {"type": "object", "properties": {
    "code": {"type": "string"}, "file": {"type": "string"}, "line": {"type": "integer"},
    "reason": {"type": "string"},
    "status": {"type": "string", "enum": ["enforced", "not_enforced", "not_applicable"]},
    "attack": {"type": "string"}, "cwe": {"type": "string"}},
    "required": ["code", "file", "line", "reason", "status", "attack", "cwe"]}

# CWE by rule type; for do_not_trust the model's own CWE is used
CWE = {"whose_data": "CWE-639", "csrf": "CWE-352", "must_not_change": "CWE-915", "limits": "CWE-1284"}


def clean(code):
    """Drop line numbers the model copied from the prompt ("  22 |     @login_required")."""
    lines = [re.sub(r"^\s*(>>)?\s*\d+\s*\|\s?", "", l) for l in (code or "").splitlines()]
    return "\n".join(l for l in lines if l.strip()).strip()


def route_code(idx, card):
    """(file, first, last) of every definition that runs for the route: route, called functions, decorators, constants, before-request hooks."""
    names = ({card["function"]} | {c["name"].split(" > ")[-1] for c in card["calls"]} | set(card["constants"])
             | {h["function"] for h in card["app_hooks"]})
    for d in card["decorators"]:
        names.add(d["name"].split("(")[0].split(".")[-1])
        names |= {u.split("(")[0].split(".")[-1] for u in d.get("uses", [])}
    out = []
    for rel, tree in idx.trees.items():
        for node in tree.body:
            name = getattr(node, "name", None) or next((t.id for t in getattr(node, "targets", [])
                                                        if isinstance(t, ast.Name)), None)
            if name in names:
                out.append((rel, span(node)[0], node.end_lineno))
    return out


def find_line(idx, card, ans):
    """(file, line, in_route) of the copied code; the route's own code is searched first, so a wrong line number does not matter."""
    code = clean(ans.get("code"))
    if not code or code.lower() == "none":
        return None, None, False
    want = ans.get("line") if isinstance(ans.get("line"), int) else 0
    ranges = route_code(idx, card)
    first_line = norm(code.splitlines()[0])
    hits = [(abs(i - want), rel, i) for rel, a, b in ranges for i in range(a, b + 1)
            if contains(norm(idx.line(rel, i)), first_line)]
    if hits:
        return min(hits)[1], min(hits)[2], True
    for rel, a, b in ranges:              # a copy over several lines, or a near copy
        line, evidence = anchor(idx.files[rel][a - 1:b], want - a + 1, code)
        if evidence != "not_found":
            return rel, a + line - 1, True
    first = idx.resolve(ans.get("file"))
    for rel in ([first] if first else []) + [f for f in idx.files if f != first]:
        line, evidence = anchor(idx.files[rel], want, code)
        if evidence != "not_found":
            return rel, line, False
    return None, None, False


def check(idx, card, ans):
    """Does the line the model cited exist, and is it part of this route's code? (ok, why)"""
    deco = re.match(r"@([\w.]+)", clean(ans.get("code")))
    if deco:            # the model often gives the file where the decorator is defined
        name = deco.group(1).split(".")[-1]
        if any(d["name"].split("(")[0].split(".")[-1] == name for d in card["decorators"]):
            return True, f"@{name} decorates this route"
        return False, f"@{name} is not a decorator of this route"
    rel, line, ok = find_line(idx, card, ans)
    if rel is None:
        return False, "the copied line is not in the code"
    if not ok:
        return False, f"{rel}:{line} is not in the code of this route"
    return True, f"found {rel}:{line}"


def finding(idx, card, rule, ans, verdict, why, admin):
    rel, line, ok = find_line(idx, card, ans)
    if not ok or clean(ans.get("code")).startswith("@"):      # point at the route's def line
        rel = card["file"]
        line = next(i for i in range(card["lines"][0], card["lines"][1] + 1)
                    if idx.line(rel, i).lstrip().startswith(("def ", "async def ")))
    if rule["type"] == "who_may_call":
        cwe = "CWE-862" if admin else "CWE-306"
    else:
        m = re.search(r"CWE-?(\d+)", ans.get("cwe") or "")
        cwe = CWE.get(rule["type"]) or (f"CWE-{m.group(1)}" if m else "CWE-602")
    return {"tool": "rule-check", "rule_id": rule["type"], "title": f"Rule not enforced: {rule['rule']}",
            "file": rel, "line": line, "snippet": idx.line(rel, line).strip(),
            "cwe": [cwe],
            # how sure we are, not how bad it is: "unverified" = only the model's word, "uncertain" = the
            # line it cited did not check out; replay.py turns it into "confirmed" or drops the finding
            "confidence": "unverified" if verdict == "not_enforced" else "uncertain",
            "extra": {"route": card["id"], "rule": rule["rule"], "verdict": verdict, "reason": why,
                      "attack": ans.get("attack", "")}}


def main():
    idx = CodeIndex(".")
    llm.check_ollama()
    cards = {card["id"]: (route, card) for route, card in rc.all_cards(idx)}
    findings, log = [], []
    for entry in json.loads(Path("runs/rules.json").read_text()):
        route, card = cards[entry["id"]]
        values = rl.client_values(idx, route, card)
        for rule in entry["rules"]:
            text = f"RULE ({rule['type']}): {rule['rule']}"
            value = next((v for v in values if v["name"] == rule["rule"].split(":")[0]), None)
            if value:
                text += "\nTHE VALUE THE RULE IS ABOUT:\n" + rl.render_values(idx, [value])
            budget = llm.code_budget(NUM_CTX, ANSWER_TOKENS, SYSTEM) - len(text)
            prompt = rl.route_prompt(idx, route, card, budget) + "\n\n" + text
            try:
                ans = llm.ask(SYSTEM, prompt, SCHEMA, NUM_CTX, max_tokens=ANSWER_TOKENS)
            except llm.LLMError as e:
                ans = {"status": "error", "reason": str(e)}
            status, why = ans.get("status"), ans.get("reason", "")
            if status == "enforced":
                ok, why = check(idx, card, ans)
                status = "enforced" if ok else "uncertain"
            if status in ("not_enforced", "uncertain"):
                findings.append(finding(idx, card, rule, ans, status, why,
                                        entry["decisions"].get("who_may_call") == "admin"))
            key = f"{entry['id']} | {rule['type']} | {rule['rule']}"
            log.append({"key": key, "status": status, "check": why, "answer": ans, "prompt": prompt})
            print(f"  {entry['id']:<42} {rule['type']:<16} {status:<15} {why[:70] if status != 'not_enforced' else ''}")

    Path("runs/enforce.json").write_text(json.dumps(findings, indent=2))
    Path("runs/enforce_log.json").write_text(json.dumps(log, indent=2))
    print(f"\n{len(findings)} findings -> runs/enforce.json")


if __name__ == "__main__":
    main()
