"""Merge warnings that point at the same problem, so each problem is reported once."""
import ast
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))
from codeindex import CodeIndex  # noqa: E402

FAMILIES = [
    {"CWE-89", "CWE-704", "CWE-564"},                  # SQL injection
    {"CWE-78", "CWE-77"},                              # command injection
    {"CWE-1336", "CWE-94", "CWE-95", "CWE-96"},        # code / template injection
    {"CWE-79", "CWE-80"},                              # XSS
    {"CWE-22", "CWE-23", "CWE-73"},                    # path traversal
    {"CWE-798", "CWE-259", "CWE-321"},                 # hardcoded secrets
    {"CWE-327", "CWE-328", "CWE-916", "CWE-759"},      # weak hashing
    {"CWE-862", "CWE-285", "CWE-639", "CWE-863"},      # access control
    {"CWE-614", "CWE-1004"},                           # cookie flags
    {"CWE-489", "CWE-215"},                            # debug mode
]
SEVERITY = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
VERDICT = {"real": 2, "uncertain": 1, "false_positive": 0}


def families(f):
    out = set()
    for cwe in f.get("cwe") or []:
        hit = {i for i, fam in enumerate(FAMILIES) if cwe in fam}
        out |= hit or {cwe}
    return out


def data_link(scope, a, b):
    """One of the two lines stores a variable that the other line uses."""
    def names(line, ctx):
        return {n.id for n in ast.walk(scope) if isinstance(n, ast.Name) and isinstance(n.ctx, ctx) and n.lineno == line}
    return bool(names(a, ast.Store) & names(b, ast.Load) or names(b, ast.Store) & names(a, ast.Load))


def same_problem(fa, fb, a, b):
    if not fa.get("line") or not fb.get("line"):            # dependency warnings
        return not fa.get("line") and not fb.get("line") and fa.get("file") == fb.get("file") \
            and a["pkg"] and a["pkg"] == b["pkg"]
    if a["rel"] is None or a["rel"] != b["rel"]:
        return False
    if fa["line"] == fb["line"]:
        return True
    return abs(fa["line"] - fb["line"]) <= 2 and a["func"] == b["func"] and \
        bool(a["fam"] & b["fam"] or (a["scope"] is not None and data_link(a["scope"], fa["line"], fb["line"])))


def merge_group(members):
    first = min(members, key=lambda f: f.get("line") or 0)
    top = max(members, key=lambda f: SEVERITY.get(f.get("severity"), 0))
    merged = dict(first)
    merged.update(
        tool="+".join(sorted({f["tool"] for f in members})), rule_id=sorted({f.get("rule_id", "") for f in members}),
        title=top.get("title"), severity=top.get("severity"),
        cwe=sorted({c for f in members for c in f.get("cwe") or []}),
        extra=dict(first.get("extra") or {}, merged_from=[
            {k: f.get(k) for k in ("tool", "rule_id", "line", "title", "cwe")} for f in members]),
    )
    merged["extra"]["n_warnings"] = len(members)
    merged["extra"]["lines"] = sorted({f["line"] for f in members if f.get("line")})
    checks = [(f.get("extra") or {}).get("verification") for f in members]
    checks = [c for c in checks if c]
    if checks:          # the strongest verdict wins
        merged["extra"]["verification"] = max(checks, key=lambda c: VERDICT.get(c.get("verdict"), 0))
    return merged


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "runs/verified.json"
    out = sys.argv[2] if len(sys.argv) > 2 else "runs/merged.json"
    findings = json.loads(Path(src).read_text())
    idx = CodeIndex(".")

    info = []
    for f in findings:
        rel = idx.resolve(f.get("file")) if f.get("line") else None
        func = idx.enclosing_function(rel, f["line"]) if rel else None
        info.append({"rel": rel, "func": (func.name, func.lineno) if func else None,
                     "scope": func or idx.trees.get(rel), "fam": families(f),
                     "pkg": (f.get("extra") or {}).get("package")})

    group = list(range(len(findings)))          # union-find: merging is transitive

    def root(i):
        while group[i] != i:
            i = group[i]
        return i

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            if same_problem(findings[i], findings[j], info[i], info[j]):
                group[root(i)] = root(j)

    groups = {}
    for i, f in enumerate(findings):
        groups.setdefault(root(i), []).append(f)
    merged = sorted((merge_group(m) for m in groups.values()), key=lambda f: (str(f.get("file")), f.get("line") or 0))
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(merged, indent=2))
    print(f"{len(findings)} warnings -> {len(merged)} items -> {out}")


if __name__ == "__main__":
    main()
