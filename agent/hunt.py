"""Baseline: the local model hunts for vulnerabilities by itself, with no scanner.

  --mode file   the model sees each file (or a piece of it) and lists every vulnerability
  --mode agent  the model starts from each route and may ask to see definitions it uses (Vulnhuntr style)
  --mode context  the model gets, for each route, all the code that runs for it (the same bundle Part 3
                  uses: route, decorators, called functions, constants, before-request hooks, templates,
                  tables) and is asked to find the vulnerabilities. Same context as Part 3, open question:
                  it separates the effect of the question from the effect of the context.

Run from the app folder:  python3 ../agent/hunt.py --mode file   (-> runs/hunt_file.json)
"""
import argparse
import ast
import json
import re
import time
from pathlib import Path

import llm
import routecard as rc
import rules as rl
from codeindex import CodeIndex, anchor, span

NUM_CTX = 4096          # every cakeshop file fits whole
ANSWER_TOKENS = 900
ROUNDS = 3              # agent mode: how many times the model may ask for more code

FINDING = {
    "type": "object",
    "properties": {
        "code": {"type": "string"},
        "line": {"type": "integer"},
        "source": {"type": "string"},
        "why": {"type": "string"},
        "title": {"type": "string"},
        "cwe": {"type": "string"},
        "severity": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
    },
    "required": ["code", "line", "source", "why", "title", "cwe", "severity"],
}

WHAT_TO_LOOK_FOR = """Look for anything an attacker could abuse, for example:
- injection: SQL, OS command, template, code, path traversal, unsafe deserialization
- cross-site scripting and open redirects
- broken access control: missing login or permission checks, users reaching other users' data
- business logic: values the server should not trust from the client, missing validation of numbers or state
- missing CSRF protection on state-changing requests
- weak cryptography or password storage, hardcoded secrets, insecure configuration
- dependencies with known vulnerabilities"""

FILE_SYSTEM = f"""You are an application-security reviewer auditing a Python Flask web application.
You are shown part of the application's source code with line numbers.
Find the security vulnerabilities in the code shown.

{WHAT_TO_LOOK_FOR}

Report only problems you can point to in the code shown. Do not report style issues.
If you find nothing, return an empty list.
For each finding give:
- code: the vulnerable line, copied exactly (without the line number)
- line: its line number
- source: where the attacker-controlled data comes from (or "none" for configuration issues)
- why: how an attacker would exploit it, in one or two sentences
- title, cwe (like "CWE-89"), severity
Reply with JSON only."""

AGENT_SYSTEM = f"""You are an application-security reviewer auditing a Python Flask web application.
You are investigating ONE route (an HTTP endpoint). Trace what an attacker can send to it
and find the security vulnerabilities it leads to, including in code it calls or templates it renders.

{WHAT_TO_LOOK_FOR}

You may not have all the code you need. You are given the names used by the route that are
defined elsewhere in the project. If you need to see some of them to decide, put their names in
"need" and leave "findings" empty. When you have enough, leave "need" empty and report.
Report only problems you can point to in the code shown.
For each finding give:
- file: the file of the vulnerable line, as written in the section header
- code: the vulnerable line, copied exactly (without the line number)
- line: its line number
- source: where the attacker-controlled data comes from
- why: how an attacker would exploit it, in one or two sentences
- title, cwe (like "CWE-639"), severity
Reply with JSON only."""

CONTEXT_SYSTEM = f"""You are an application-security reviewer auditing a Python Flask web application.
You are investigating ONE route (an HTTP endpoint). You are given all the code that runs when the route is
called: the route, its decorators, the functions it calls, constants, code that runs before every request,
the templates it renders and the database tables it uses, each with its file and line numbers.
Trace what an attacker can send to it and find the security vulnerabilities it leads to.

{WHAT_TO_LOOK_FOR}

Report only problems you can point to in the code shown.
For each finding give:
- file: the file of the vulnerable line, as written in the section header
- code: the vulnerable line, copied exactly (without the line number)
- line: its line number
- source: where the attacker-controlled data comes from
- why: how an attacker would exploit it, in one or two sentences
- title, cwe (like "CWE-639"), severity
Reply with JSON only."""

FILE_SCHEMA = {"type": "object", "properties": {"findings": {"type": "array", "items": FINDING}},
               "required": ["findings"]}


def agent_schema(may_ask):
    item = {**FINDING, "properties": {"file": {"type": "string"}, **FINDING["properties"]},
            "required": ["file"] + FINDING["required"]}
    props = {"findings": {"type": "array", "items": item}}
    if may_ask:
        props = {"need": {"type": "array", "items": {"type": "string"}}, **props}
    return {"type": "object", "properties": props, "required": list(props)}


def ask(system, prompt, schema):
    try:
        return llm.ask(system, prompt, schema, NUM_CTX, max_tokens=ANSWER_TOKENS)
    except llm.LLMError as e:
        return {"error": str(e), "findings": []}


def numbered(lines, start, end):
    return "\n".join(f"{i:>4} | {lines[i - 1]}" for i in range(start, end + 1))


def load_sources(idx):
    files = dict(idx.files)
    for path in sorted(idx.root.glob("requirements*.txt")):
        files[path.name] = path.read_text(errors="replace").splitlines()
    return files


def pieces(idx, rel, lines, budget):
    """Cut a file into (start, end) ranges that fit the budget, between top-level statements if possible."""
    if not lines:
        return []
    n = len(lines)
    size = lambda a, b: len(numbered(lines, a, b))
    if rel in idx.trees:
        starts = {1} | {span(node)[0] for node in idx.trees[rel].body}
    else:
        starts = set(range(1, n + 1))
    bounds = sorted(starts | {n + 1})
    out, a = [], 1
    while a <= n:
        fits = [s for s in bounds if s > a and size(a, s - 1) <= budget]
        if fits:
            b = max(fits) - 1
        else:                       # one statement is too big: cut it line by line
            b = a
            while b < n and size(a, b + 1) <= budget:
                b += 1
        out.append((a, b))
        a = b + 1
    return out


def to_finding(raw, rel, files, mode, where):
    """The model's finding in the format of findings.json, with the line fixed from the copied code."""
    lines = files.get(rel, [])
    line, evidence = anchor(lines, raw.get("line"), raw.get("code"))
    snippet = lines[line - 1].strip() if isinstance(line, int) and 1 <= line <= len(lines) else raw.get("code", "")
    m = re.search(r"(\d{2,4})", str(raw.get("cwe") or ""))
    return {"tool": "llm-hunt", "rule_id": mode, "title": raw.get("title", ""), "file": rel, "line": line,
            "snippet": snippet, "severity": raw.get("severity", "MEDIUM"), "cwe": [f"CWE-{m.group(1)}"] if m else [],
            "extra": {"source": raw.get("source", ""), "why": raw.get("why", ""), "evidence": evidence,
                      "model_line": raw.get("line"), "model_code": raw.get("code", ""), "where": where}}


def hunt_files(idx, files, log):
    budget = llm.code_budget(NUM_CTX, ANSWER_TOKENS, FILE_SYSTEM)
    findings = []
    for rel, lines in files.items():
        for a, b in pieces(idx, rel, lines, budget):
            where = f"{rel}:{a}-{b}"
            prompt = f"File: {rel} (lines {a}-{b} of {len(lines)})\n\n{numbered(lines, a, b)}"
            t0 = time.time()
            answer = ask(FILE_SYSTEM, prompt, FILE_SCHEMA)
            log.append({"where": where, "prompt": prompt, "answer": answer, "seconds": round(time.time() - t0, 1)})
            got = [to_finding(f, rel, files, "file", where) for f in answer.get("findings", [])]
            findings += got
            print(f"  {where:<40} {len(got)} finding(s)  {log[-1]['seconds']}s" + ("  ERROR" if "error" in answer else ""))
    return findings


def project_names(idx, node):
    """Names used in a function that are defined elsewhere in the project, plus templates it renders."""
    used = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    names = sorted(u for u in used if u in idx.defs and u != node.name)
    templates = sorted({sub.args[0].value for sub in ast.walk(node)
                        if isinstance(sub, ast.Call) and getattr(sub.func, "id", None) == "render_template"
                        and sub.args and isinstance(sub.args[0], ast.Constant)})
    return names + templates


def lookup(idx, files, rel, name):
    """(file, start, end) of a requested definition or template, or None."""
    name = name.strip()
    if name.endswith(".html"):
        hits = [r for r in files if r.endswith("templates/" + name) or r.endswith("/" + name)]
        return (hits[0], 1, len(files[hits[0]])) if hits else None
    name = name.split("(")[0].split(".")[-1]
    found = (idx.visible_def(rel, name) if rel in idx.trees else None) or (idx.defs.get(name) or [None])[0]
    if not found:
        return None
    return (found[0], *span(found[1]))


def section(files, rel, a, b, title):
    return f"--- {title}: {rel} (lines {a}-{b}) ---\n{numbered(files[rel], a, b)}"


def hunt_routes(idx, files, log):
    budget = llm.code_budget(NUM_CTX, ANSWER_TOKENS, AGENT_SYSTEM)
    findings = []
    for route in rc.find_routes(idx):
        rel, node = route["file"], route["node"]
        first, last = span(node)
        names = project_names(idx, node)
        header = (f"Route: {', '.join(route['methods'])} {route['url']}  (function {route['function']} in {rel})\n"
                  f"Names used here that are defined elsewhere in the project: {', '.join(names) or 'none'}\n")
        sections = [section(files, rel, first, last, "ROUTE")]
        shown = {(rel, first)}
        where = f"{route['url']} [{rel}:{route['function']}]"
        entry = {"where": where, "rounds": []}
        log.append(entry)
        t0 = time.time()
        for rnd in range(ROUNDS + 1):
            may_ask = rnd < ROUNDS
            note = "" if may_ask else "\nYou cannot ask for more code now. Report your findings.\n"
            prompt = header + note + "\n" + "\n\n".join(sections)
            answer = ask(AGENT_SYSTEM, prompt, agent_schema(may_ask))
            step = {"prompt": prompt, "answer": answer}
            entry["rounds"].append(step)
            need = [n for n in answer.get("need", []) if n.strip()] if may_ask else []
            if not need or answer.get("findings"):
                break
            added, missing = [], []
            for name in need[:4]:
                hit = lookup(idx, files, rel, name)
                if not hit or (hit[0], hit[1]) in shown:
                    missing.append(name)
                    continue
                text = section(files, hit[0], hit[1], hit[2], f"CONTEXT {name}")
                if len("\n\n".join(sections + [text])) + len(header) > budget:
                    missing.append(name + " (no room)")
                    continue
                sections.append(text)
                shown.add((hit[0], hit[1]))
                added.append(name)
            step.update(added=added, missing=missing)
            if not added:               # nothing new to show: the next round must answer
                header += f"\nNot available: {', '.join(missing)}\n"
        entry["seconds"] = round(time.time() - t0, 1)
        got = []
        for f in answer.get("findings", []):
            frel = idx.resolve(f.get("file")) or (f.get("file") if f.get("file") in files else rel)
            got.append(to_finding(f, frel, files, "agent", where))
        findings += got
        asked = sum(len(s.get("added", [])) for s in entry["rounds"])
        print(f"  {where:<45} {len(entry['rounds'])} round(s), {asked} definition(s) shown, "
              f"{len(got)} finding(s)  {entry['seconds']}s" + ("  ERROR" if "error" in answer else ""))
    return findings


def hunt_context(idx, files, log):
    """One question per route, with the full Part 3 code bundle up front and no tool to ask for more."""
    budget = llm.code_budget(NUM_CTX, ANSWER_TOKENS, CONTEXT_SYSTEM)
    schema = agent_schema(may_ask=False)
    findings = []
    for route, card in rc.all_cards(idx):
        where = f"{route['url']} [{route['file']}:{route['function']}]"
        prompt = rl.route_prompt(idx, route, card, budget)
        t0 = time.time()
        answer = ask(CONTEXT_SYSTEM, prompt, schema)
        log.append({"where": where, "prompt": prompt, "answer": answer, "seconds": round(time.time() - t0, 1)})
        got = []
        for f in answer.get("findings", []):
            frel = idx.resolve(f.get("file")) or (f.get("file") if f.get("file") in files else route["file"])
            got.append(to_finding(f, frel, files, "context", where))
        findings += got
        cut = "  (sections left out for space)" if "left out for space" in prompt else ""
        print(f"  {where:<45} {len(got)} finding(s)  {log[-1]['seconds']}s{cut}"
              + ("  ERROR" if "error" in answer else ""))
    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["file", "agent", "context"], default="file")
    mode = ap.parse_args().mode
    idx = CodeIndex(".")
    files = load_sources(idx)
    llm.check_ollama()

    t0, log = time.time(), []
    hunt = {"file": hunt_files, "agent": hunt_routes, "context": hunt_context}[mode]
    findings = hunt(idx, files, log)
    seen, unique = set(), []                 # the model sometimes repeats a finding
    for f in findings:
        key = (f["file"], f["line"], tuple(f["cwe"]))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    Path("runs").mkdir(exist_ok=True)
    Path(f"runs/hunt_{mode}.json").write_text(json.dumps(unique, indent=2))
    Path(f"runs/hunt_{mode}_log.json").write_text(json.dumps(log, indent=2))
    made_up = sum(f["extra"]["evidence"] == "not_found" for f in unique)
    print(f"\n{len(unique)} findings ({len(findings) - len(unique)} duplicates removed, {made_up} with made-up code) "
          f"-> runs/hunt_{mode}.json   {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
