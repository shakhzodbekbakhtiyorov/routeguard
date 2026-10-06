"""Checker: is each scanner warning real? Fixed rules first, the local model for the rest."""
import ast
import json
import re
import time
from collections import Counter
from pathlib import Path

import llm
from codeindex import CodeIndex, call_name, decorator_names, span

NUM_CTX = 2048
ANSWER_TOKENS = 300
VOTES = 3
ESCALATE_VOTES = 5
ESCALATE_AGREEMENT = 0.8     # 4 of 5

CWE_NAMES = {
    "CWE-22": "path traversal", "CWE-73": "external control of file name or path",
    "CWE-78": "OS command injection", "CWE-77": "command injection",
    "CWE-79": "cross-site scripting (XSS)", "CWE-89": "SQL injection",
    "CWE-94": "code injection", "CWE-95": "eval injection", "CWE-96": "code/template injection",
    "CWE-1336": "server-side template injection", "CWE-502": "deserialization of untrusted data",
    "CWE-601": "open redirect", "CWE-614": "cookie without Secure/HttpOnly flags",
    "CWE-704": "SQL injection (string-built query)",
    "CWE-639": "insecure direct object reference (missing ownership check)",
    "CWE-862": "missing authorization", "CWE-285": "improper authorization",
    "CWE-915": "mass assignment", "CWE-602": "client-side enforcement of server-side security",
    "CWE-1284": "missing validation of a quantity/number", "CWE-20": "improper input validation",
    "CWE-352": "cross-site request forgery", "CWE-798": "hardcoded credentials",
    "CWE-259": "hardcoded password", "CWE-327": "broken or risky crypto", "CWE-916": "weak password hashing",
    "CWE-489": "debug mode enabled",
}
SECRET_CWES = {"CWE-798", "CWE-259", "CWE-321"}
HASH_CWES = {"CWE-327", "CWE-328", "CWE-916", "CWE-759"}
SQL_CWES = {"CWE-89", "CWE-704", "CWE-564"}

SYSTEM_PROMPT = """You are a careful application-security reviewer. A line in a Python Flask web app was flagged as a POSSIBLE weakness. Automated flags are often false alarms. Decide if the flagged line (marked >>) is really exploitable, using only the code shown.

Answer in this order:
1. source: where does the data used on the flagged line come from? (HTTP query/form/cookie/header, user-written database content, a constant, server config, nothing)
2. path: how does that data reach the flagged line?
3. protection: what, if anything, stops an attacker? Only count protections that are VISIBLE in the code shown (for example an allow-list check, a parameterized query, an auth decorator).
4. verdict: "real" if attacker-controlled data reaches the line without effective protection; "false_positive" if the data is constant/allow-listed/otherwise protected or the line is not dangerous; "uncertain" only if the code needed to decide is not shown.

Sections labelled CONTEXT ONLY are there to help you trace data. Judge the flagged line, not the context.
Reply with JSON only."""

# the model writes keys in schema order, so the reasoning comes before the verdict
SCHEMA = {
    "type": "object",
    "properties": {
        "source": {"type": "string"},
        "path": {"type": "string"},
        "protection": {"type": "string"},
        "verdict": {"type": "string", "enum": ["real", "false_positive", "uncertain"]},
    },
    "required": ["source", "path", "protection", "verdict"],
}


def one_line(text):
    return re.sub(r"\s+", " ", text or "").strip()


def evidence_check(idx, f):
    """Is the code the scanner quoted really at (or within 2 lines of) the reported line?"""
    rel = idx.resolve(f.get("file"))
    if rel is None:
        return False, f"file not found in project: {f.get('file')}"
    line = f.get("line")
    if line is None:
        return False, "no line number"
    lines = idx.files[rel]
    if not 1 <= line <= len(lines):
        return False, f"line {line} outside file ({len(lines)} lines)"
    snippet = one_line(f["snippet"].splitlines()[0] if f.get("snippet") else "")
    if not snippet:
        return True, "no snippet given; line exists"
    for n in range(max(1, line - 2), min(len(lines), line + 2) + 1):
        code = one_line(lines[n - 1])
        if code and (snippet[:80] in code or code in snippet):
            return True, "snippet found" + ("" if n == line else f" at line {n}")
    return False, "snippet not found near the reported line"


def is_string_list(node):
    """ALLOWED = {"a", "b"}, also frozenset([...]), set(...), tuple(...)."""
    value = getattr(node, "value", None)
    if isinstance(value, ast.Call) and call_name(value) in ("frozenset", "set", "tuple") and value.args:
        value = value.args[0]
    return isinstance(value, (ast.Set, ast.List, ast.Tuple)) and all(
        isinstance(e, ast.Constant) and isinstance(e.value, str) for e in value.elts)


def stops(statements):
    for st in statements:
        if isinstance(st, (ast.Raise, ast.Return, ast.Continue, ast.Break)):
            return True
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and call_name(st.value) in ("abort", "exit"):
            return True
    return False


def allowlist_check(idx, rel, func, name, call):
    """The constant allow-list `name` is checked against before `call` (if name in ALLOWED: ...call... / if name not in ALLOWED: raise)."""
    for node in ast.walk(func):
        test = node.test if isinstance(node, ast.If) else None
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name)
                and test.left.id == name and isinstance(test.comparators[0], ast.Name)):
            continue
        allow = test.comparators[0].id
        d = idx.visible_def(rel, allow)
        if not d or not is_string_list(d[1]):
            continue
        if isinstance(test.ops[0], ast.In) and any(n is call for b in node.body for n in ast.walk(b)):
            return allow
        if isinstance(test.ops[0], ast.NotIn) and node.lineno < call.lineno and stops(node.body):
            return allow
    return None


def sql_allowlist_rule(idx, rel, line, func):
    """f-string SQL is safe if every inserted name was checked against a fixed allow-list."""
    for call in ast.walk(func):
        if not (isinstance(call, ast.Call) and call_name(call) == "execute" and call.args
                and call.lineno <= line <= (call.end_lineno or call.lineno)
                and isinstance(call.args[0], ast.JoinedStr)):
            continue
        inserted = [v for v in call.args[0].values if isinstance(v, ast.FormattedValue)]
        if not inserted or not all(isinstance(v.value, ast.Name) for v in inserted):
            return None
        checks = {v.value.id: allowlist_check(idx, rel, func, v.value.id, call) for v in inserted}
        if all(checks.values()):
            desc = ", ".join(f"{n} (checked against {a})" for n, a in checks.items())
            return ("false_positive", f"the f-string only inserts {desc}, a fixed allow-list of names, "
                    "before the query runs; user values are passed separately as parameters")
    return None


def rule_check(idx, rel, line, cwes):
    """(verdict, reason) if a fixed rule decides, else None."""
    code = idx.line(rel, line)
    if re.match(r"^(import\s+\S+|from\s+\S+\s+import\s+)", code.strip()):
        return "false_positive", "import statement only; importing a module is not a vulnerability by itself"
    func = idx.enclosing_function(rel, line)
    if cwes & SECRET_CWES:
        if re.search(r"os\.environ|getenv\(", code):
            return "false_positive", "value is read from the environment, not hardcoded"
        if re.search(r"""(?i)\b\w*(secret|key|passw(or)?d|token)\w*['"]?\]?\s*[=:]\s*["'][^"']{4,}["']""", code):
            return "real", "secret/key assigned a string literal in source code"
    if cwes & HASH_CWES and re.search(r"\b(md5|sha1)\b", code):
        names = " ".join([func.name if func else "", code] + [a.arg for a in (func.args.args if func else [])])
        if re.search(r"(?i)passw|pwd", names):
            return "real", f"fast unsalted hash ({'md5' if 'md5' in code else 'sha1'}) used for passwords"
    if cwes & SQL_CWES and func is not None:
        decided = sql_allowlist_rule(idx, rel, line, func)
        if decided:
            return decided
    if re.search(r"debug\s*=\s*True", code):
        return "real", "debug mode enabled in code"
    return None


def build_context(idx, rel, line, limit):
    """The flagged function plus CONTEXT ONLY sections, cut to `limit` characters."""
    sections, seen = [], set()

    def add(title, body):
        sections.append(f"### {title}\n{body}")

    def add_def(name, title, max_lines):
        found = idx.visible_def(rel, name)
        if found and (found[0], name) not in seen:
            seen.add((found[0], name))
            add(title.format(file=found[0]), idx.source(found[0], found[1], max_lines=max_lines))

    func = None if rel.endswith(".html") else idx.enclosing_function(rel, line)
    if rel.endswith(".html"):
        add(f"{rel} (template; flagged line marked >>)", idx.numbered(rel, line - 6, line + 6, mark=line))
        template_context(idx, rel, add)
    elif func is None:
        add(f"{rel} (module level; flagged line marked >>)", idx.numbered(rel, line - 6, line + 6, mark=line))
    else:
        add(f"{rel}: {func.name}() containing the flagged line (marked >>)", idx.source(rel, func, mark=line))
        seen.add((rel, func.name))
        for name in decorator_names(func):
            add_def(name, f"CONTEXT ONLY: {{file}} decorator {name}", 25)
        for name in sorted({n.id for n in ast.walk(func) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}):
            found = idx.visible_def(rel, name)
            if found and isinstance(found[1], (ast.Assign, ast.AnnAssign)) and not isinstance(found[1].value, ast.Call):
                add_def(name, f"CONTEXT ONLY: {{file}} value of {name}", 12)
        for name in idx.calls_on_line(func, line):
            found = idx.visible_def(rel, name)
            if found and isinstance(found[1], ast.FunctionDef):
                add_def(name, f"CONTEXT ONLY: {{file}} {name}() called on the flagged line", 25)
        if func.args.args:          # without parameters, callers cannot pass data in
            for crel, node in idx.callers(func.name):
                if (crel, node.name) not in seen:
                    seen.add((crel, node.name))
                    add(f"CONTEXT ONLY: {crel} {node.name}() calls {func.name}()", idx.source(crel, node))

    text = "\n\n".join(sections)
    while len(text) > limit and len(sections) > 1:
        sections.pop()
        text = "\n\n".join(sections) + "\n\n(further context omitted)"
    return text[:limit]


def template_context(idx, rel, add):
    """The views that render a template, and functions that store request data in the tables it shows."""
    tables, shown = set(), set()
    for vrel, node in idx.views_of_template(rel):
        add(f"CONTEXT ONLY: {vrel} view {node.name}() renders this template", idx.source(vrel, node))
        shown.add((vrel, node.name))
        first, last = span(node)
        tables |= set(re.findall(r"FROM\s+(\w+)", "\n".join(idx.files[vrel][first - 1:last]), re.I))
    for vrel, node in idx.functions():
        if not isinstance(node, ast.FunctionDef) or (vrel, node.name) in shown:
            continue
        first, last = span(node)
        src = "\n".join(idx.files[vrel][first - 1:last])
        if "request." in src and any(re.search(rf"(INSERT\s+INTO|UPDATE)\s+{t}\b", src, re.I) for t in tables):
            add(f"CONTEXT ONLY: {vrel} {node.name}() stores request data in a table this template shows",
                idx.source(vrel, node))


def build_prompt(idx, rel, line, cwes, num_ctx):
    weakness = ", ".join(sorted({CWE_NAMES.get(c, c) for c in cwes}) or ["a security weakness"])
    context = build_context(idx, rel, line, llm.code_budget(num_ctx, ANSWER_TOKENS, SYSTEM_PROMPT))
    return (f"FLAGGED LINE\nlocation: {rel} line {line}\ncode: {idx.line(rel, line).strip()}\n"
            f"possible weakness: {weakness}\n\n"
            f"CODE\n{context}\n\n"
            "Is the flagged line really exploitable? Fill in source, path, protection, then verdict.")


def model_check(idx, rel, line, cwes):
    """3 votes; on a split vote ask again with twice the context and 5 votes."""
    def ask(num_ctx, votes):
        prompt = build_prompt(idx, rel, line, cwes, num_ctx)
        verdict, agreement, best, verdicts = llm.vote(SYSTEM_PROMPT, prompt, SCHEMA, votes, num_ctx)
        # "reason" is only there when the call failed
        reason = best.get("reason") or " | ".join(f"{k}: {best[k]}" for k in ("source", "path", "protection")
                                                  if best.get(k))
        return {"verdict": verdict, "agreement": round(agreement, 2), "source": best.get("source"),
                "path": best.get("path"), "protection": best.get("protection"), "reason": reason,
                "votes": verdicts}

    rec = {"stage": "llm", **ask(NUM_CTX, VOTES)}
    if len(set(rec["votes"])) > 1:
        again = ask(NUM_CTX * 2, ESCALATE_VOTES)
        if again["agreement"] < ESCALATE_AGREEMENT:
            again["verdict"] = "uncertain"
        rec.update(stage="llm+escalated", first_votes=rec["votes"], **again, needs_human=again["verdict"] == "uncertain")
    return rec


def main():
    idx = CodeIndex(".")
    findings = json.loads(Path("findings.json").read_text())
    llm.check_ollama()

    # dependency warnings and missing evidence are decided here; the rest is grouped by line
    records = [None] * len(findings)
    lines = {}
    for i, f in enumerate(findings):
        if f.get("line") is None and str(f.get("file") or "").endswith(".txt"):
            records[i] = {"stage": "advisory", "verdict": "real",
                          "reason": "pinned version is listed in a vulnerability advisory database"}
            continue
        ok, why = evidence_check(idx, f)
        if ok:
            lines.setdefault((idx.resolve(f["file"]), f["line"]), []).append(i)
        else:
            records[i] = {"stage": "evidence", "verdict": "false_positive", "reason": why}

    start = time.time()
    print(f"{len(findings)} findings -> {len(lines)} code lines to check\n")
    for n, ((rel, line), members) in enumerate(sorted(lines.items()), 1):
        cwes = set().union(*(findings[i].get("cwe") or [] for i in members))
        decided = rule_check(idx, rel, line, cwes)
        if decided:
            rec = {"stage": "rule", "verdict": decided[0], "reason": decided[1]}
        else:
            rec = model_check(idx, rel, line, cwes)
        for i in members:
            records[i] = rec
        print(f"[{n:>2}/{len(lines)}] {rec['verdict']:<14} {rec['stage']:<8} {str(rec.get('votes', '')):<36} {rel}:{line}",
              flush=True)

    log = []
    for f, rec in zip(findings, records):
        rec = dict(rec, model=llm.MODEL if rec["stage"].startswith("llm") else None)
        log.append(dict(f, extra=dict(f.get("extra") or {}, verification=rec)))
    kept = [f for f in log if f["extra"]["verification"]["verdict"] in ("real", "uncertain")]
    Path("runs").mkdir(exist_ok=True)
    Path("runs/verified_log.json").write_text(json.dumps(log, indent=2))
    Path("runs/verified.json").write_text(json.dumps(kept, indent=2))
    counts = Counter(f["extra"]["verification"]["verdict"] for f in log)
    print(f"\n{dict(counts)}  kept {len(kept)}/{len(log)}  in {time.time() - start:.0f}s -> runs/verified.json")


if __name__ == "__main__":
    main()
