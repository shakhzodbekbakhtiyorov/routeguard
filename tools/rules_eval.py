"""Score the rules from rules.py against labels/expected_rules.json, and write them as readable text."""
import json
from pathlib import Path


def main():
    expected = json.loads(Path("labels/expected_rules.json").read_text())["routes"]
    runs = {r["url"]: r for r in json.loads(Path("runs/rules.json").read_text())}

    must_rows, csrf_hits, csrf_total = [], 0, 0
    req_hit = req_total = extra = total_rules = errors = 0
    lines = []
    for url, exp in expected.items():
        got = runs.get(url, {"rules": [], "error": "route not in the run"})
        rules = got["rules"]
        types = {r["type"] for r in rules}
        errors += bool(got.get("error"))
        total_rules += len(rules)
        req_total += len(exp["required"])
        req_hit += len(set(exp["required"]) & types)
        extras = [r for r in rules if r["type"] not in set(exp["required"]) | set(exp["optional"])]
        extra += len(extras)
        for m in exp["must"]:
            ok = any(r["type"] == m["type"] and (not m["keywords"] or
                     any(k in (r["rule"] + " " + r["applies_because"]).lower() for k in m["keywords"]))
                     for r in rules)
            if m["label"] == "V19":
                csrf_total += 1
                csrf_hits += ok
            else:
                must_rows.append((m["label"], url, m["type"], ok))
        missing = sorted(set(exp["required"]) - types)
        lines.append(f"{url}   [{', '.join(sorted(types)) or 'no rules'}]"
                     + (f"   MISSING: {', '.join(missing)}" if missing else "")
                     + (f"   ERROR: {got['error']}" if got.get("error") else ""))
        for r in rules:
            lines.append(f"   - {r['type']:<16} {r['rule']}" + ("  EXTRA" if r in extras else ""))
            lines.append(f"     {'':<16} because: {r['applies_because']}")
        lines.append("")

    v19 = csrf_total and csrf_hits * 2 > csrf_total
    found = sum(ok for *_, ok in must_rows) + bool(v19)
    print("rules needed for the labelled bugs / decoys:")
    for label, url, typ, ok in sorted(must_rows):
        print(f"  {'yes' if ok else 'NO ':<4} {label}  {typ:<16} {url}")
    print(f"  {'yes' if v19 else 'NO ':<4} V19  csrf             on {csrf_hits}/{csrf_total} POST routes")
    print(f"must: {found}/{len(must_rows) + 1}")
    print(f"required rule types written: {req_hit}/{req_total} ({req_hit / req_total:.0%})")
    print(f"extra rules (type does not fit the route): {extra} of {total_rules} rules")
    if errors:
        print(f"routes with errors: {errors}")
    Path("runs/rules.txt").write_text("\n".join(lines))
    summary = {"must_found": found, "must_total": len(must_rows) + 1,
               "must": {f"{l} {u}": ok for l, u, _, ok in must_rows}, "csrf_routes": [csrf_hits, csrf_total],
               "required_hit": req_hit, "required_total": req_total, "extra": extra, "n_rules": total_rules}
    Path("runs/rules_score.json").write_text(json.dumps(summary, indent=2))
    print("readable list -> runs/rules.txt")


if __name__ == "__main__":
    main()
