"""How good is the checker (verify.py)? Its verdict on every scanner warning, against the answer key."""
import json
from collections import Counter, defaultdict
from pathlib import Path

import score


def main():
    labels = score.load_labels()
    vulns, decoys = labels["vulnerabilities"], labels["decoys"]
    rows = []
    for f in json.loads(Path("runs/verified_log.json").read_text()):
        group, label, _ = score.classify(f, vulns, decoys)
        v = f["extra"]["verification"]
        rows.append({"real": group == "vuln", "group": group, "label": label["id"] if label else "-",
                     "kept": v["verdict"] in ("real", "uncertain"), "stage": v["stage"], "verdict": v["verdict"],
                     "where": f"{f['tool']:<9} {f['file']}:{f['line']}"})

    n = Counter((r["real"], r["kept"]) for r in rows)
    tp, fn, fp, tn = n[(True, True)], n[(True, False)], n[(False, True)], n[(False, False)]
    print(f"\n{len(rows)} scanner warnings ({tp + fn} on a real bug, {fp + tn} not)\n")
    print("                     kept   removed")
    print(f"  real bug           {tp:>4}   {fn:>7}")
    print(f"  not a real bug     {fp:>4}   {tn:>7}")
    print(f"\nprecision: scanners alone {(tp + fn) / len(rows):.0%} -> after checker {tp / (tp + fp) if tp + fp else 0:.0%}")

    print("\nwho decided:")
    by_stage = defaultdict(Counter)
    for r in rows:
        by_stage[r["stage"]][(r["real"], r["kept"])] += 1
    for stage, c in by_stage.items():
        print(f"  {stage:<16} real kept {c[(True, True)]:>2}  real removed {c[(True, False)]:>2}  "
              f"false alarm kept {c[(False, True)]:>2}  false alarm removed {c[(False, False)]:>2}")

    before = {r["label"] for r in rows if r["real"]}
    after = {r["label"] for r in rows if r["real"] and r["kept"]}
    print(f"\nbugs: scanners hit {len(before)}/{len(vulns)}, still found after the checker {len(after)}/{len(vulns)}")
    for vid in sorted(before - after):
        print(f"  lost by the checker: {vid}")
    print("\nmistakes:")
    for r in rows:
        if r["real"] != r["kept"]:
            what = "real bug removed " if r["real"] else "false alarm kept "
            print(f"  {what} [{r['group']} {r['label']}] {r['stage']:<14} {r['verdict']:<14} {r['where']}")


if __name__ == "__main__":
    main()
