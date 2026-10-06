"""Score findings against the answer key (labels/ground_truth.json).

A finding hits a label if it is in the same file within 2 lines of the label's anchor (same package for
a dependency, same CWE for an app-wide bug). --strict also requires the CWE to match (exact or related),
so a finding on the right line for the wrong reason does not count.

Run from the app folder:
  python3 ../tools/score.py runs/replay.json [--strict]
  python3 ../tools/score.py runs/merged.json runs/replay.json     # several files scored as one
  python3 ../tools/score.py --check-labels                        # every anchor must match one line
  python3 ../tools/score.py runs/merged.json runs/replay.json --hand   # apply labels/hand_check.json

--hand applies the hand check in labels/hand_check.json: findings the scorer misses because they sit a few
lines from the label anchor are credited to their bug, real problems the answer key does not list count as
real (precision, not recall), and listed false alarms stay false alarms.
"""
import argparse
import json
import re
import sys
from pathlib import Path

LABELS = "labels/ground_truth.json"
HAND = "labels/hand_check.json"
TOLERANCE = 2
RELATED_CWES = {
    "CWE-798": {"CWE-259", "CWE-321"},
    "CWE-916": {"CWE-327", "CWE-328", "CWE-759"},
    "CWE-1336": {"CWE-94", "CWE-95", "CWE-96"},
    "CWE-22": {"CWE-23", "CWE-73"},
    "CWE-639": {"CWE-284", "CWE-285", "CWE-862", "CWE-863"},
    "CWE-862": {"CWE-284", "CWE-285", "CWE-863"},
    "CWE-915": {"CWE-269", "CWE-284"},
    "CWE-602": {"CWE-20", "CWE-472", "CWE-807"},
    "CWE-1284": {"CWE-20"},
    "CWE-489": {"CWE-215", "CWE-94"},
    "CWE-1395": {"CWE-1104", "CWE-937"},
    "CWE-79": {"CWE-80"},
    "CWE-78": {"CWE-77"},
}
DEPENDENCY = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[=<>!~]=")


def clean(path):
    p = str(path).replace("\\", "/") if path else None
    while p and p.startswith("./"):
        p = p[2:]
    return p


def same_file(a, b):
    a, b = clean(a), clean(b)
    return bool(a and b) and (a == b or a.endswith("/" + b) or b.endswith("/" + a))


def load_labels():
    """The answer key, with each label's kind and the line numbers of its anchors."""
    data = json.loads(Path(LABELS).read_text())
    for label in data["vulnerabilities"] + data["decoys"]:
        label["lines"] = []
        if not label.get("file") or not label.get("anchor"):
            label["kind"] = "app-wide"
        elif DEPENDENCY.match(label["anchor"]) and label["file"].endswith(".txt"):
            label["kind"] = "dependency"
            label["package"] = DEPENDENCY.match(label["anchor"]).group(1).lower()
        else:
            label["kind"] = "code"
        if label.get("file") and label.get("anchor") and Path(label["file"]).exists():
            anchors = [label["anchor"]] + list(label.get("alt_anchors") or [])
            label["lines"] = [i for i, text in enumerate(Path(label["file"]).read_text().splitlines(), 1)
                              if any(a in text for a in anchors)]
    return data


def cwe_match(finding, label):
    """2 = exact CWE, 1 = related CWE, 0 = no match."""
    want, got = label.get("cwe") or label.get("looks_like"), set(finding.get("cwe") or [])
    if not want or not got:
        return 0
    return 2 if want in got else 1 if got & RELATED_CWES.get(want, set()) else 0


def package(finding):
    name = (finding.get("extra") or {}).get("package")
    if not name:
        m = DEPENDENCY.match(finding.get("snippet") or "")
        name = m.group(1) if m else None
    return name.lower() if name else None


def distance(finding, label):
    """How far the finding is from the label, or None if it does not hit it."""
    if label["kind"] == "app-wide":
        return 0 if cwe_match(finding, label) else None
    if not same_file(finding.get("file"), label.get("file")):
        return None
    if label["kind"] == "dependency":
        return 0 if package(finding) == label["package"] else None
    line = finding.get("line")
    if line is None or not label["lines"]:
        return None
    d = min(abs(line - n) for n in label["lines"])
    return d if d <= TOLERANCE else None


def classify(finding, vulns, decoys, strict=False):
    """("vuln" | "decoy" | "other", label, CWE match). The best CWE match wins, then the nearest label."""
    hits = [(group, label, d, cwe_match(finding, label))
            for group, labels in (("vuln", vulns), ("decoy", decoys)) for label in labels
            for d in [distance(finding, label)] if d is not None]
    if strict:
        hits = [h for h in hits if h[3] > 0]
    if not hits:
        return "other", None, 0
    group, label, _, level = min(hits, key=lambda h: (-h[3], h[2], 0 if h[0] == "vuln" else 1))
    return group, label, level


def load_hand():
    p = Path(HAND)
    return json.loads(p.read_text())["findings"] if p.exists() else []


def hand_verdict(finding, hand):
    """The hand-check entry for this finding, if any."""
    for h in hand:
        if h.get("tool") != finding.get("tool"):
            continue
        if "package" in h:
            if package(finding) == h["package"]:
                return h
            continue
        if not same_file(h.get("file"), finding.get("file")) or h.get("line") != finding.get("line"):
            continue
        if "route" in h and h["route"] != (finding.get("extra") or {}).get("route"):
            continue
        return h
    return None


def check_labels():
    data = json.loads(Path(LABELS).read_text())
    problems = 0
    for label in data["vulnerabilities"] + data["decoys"]:
        if not label.get("file") or not label.get("anchor"):
            continue
        if not Path(label["file"]).exists():
            print(f"  {label['id']}: file not found: {label['file']}")
            problems += 1
            continue
        text = Path(label["file"]).read_text().splitlines()
        for anchor in [label["anchor"]] + list(label.get("alt_anchors") or []):
            n = sum(anchor in line for line in text)
            if n != 1:
                print(f"  {label['id']}: anchor {anchor!r} matches {n} lines (need exactly 1)")
                problems += 1
    sys.exit(f"{problems} label(s) need fixing") if problems else print("All anchors match exactly one line.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", nargs="*")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--check-labels", action="store_true")
    ap.add_argument("--hand", action="store_true", help="apply labels/hand_check.json")
    args = ap.parse_args()
    if args.check_labels:
        return check_labels()
    if not args.findings:
        ap.error("give at least one findings file")

    labels = load_labels()
    vulns, decoys = labels["vulnerabilities"], labels["decoys"]
    by_id = {v["id"]: v for v in vulns}
    hand = load_hand() if args.hand else []
    real_unlabelled = 0
    findings = [f for path in args.findings for f in json.loads(Path(path).read_text())]
    name = "+".join(Path(p).stem for p in args.findings)

    found, best_cwe, decoy_hits, other = {}, {}, {}, []
    hits = code_total = code_hits = 0          # code_*: without dependency findings
    for f in findings:
        group, label, level = classify(f, vulns, decoys, args.strict)
        h = hand_verdict(f, hand) if args.hand else None
        if h and h["verdict"] in by_id:
            group, label, level = "vuln", by_id[h["verdict"]], max(cwe_match(f, by_id[h["verdict"]]), 1)
        elif h and h["verdict"] == "real":
            real_unlabelled += 1
            hits += 1
            code_hits += package(f) is None
            code_total += package(f) is None
            continue
        elif h and h["verdict"] == "false_alarm":
            group, label = "other", None
        dependency = (group == "vuln" and label["kind"] == "dependency") or (group == "other" and package(f) is not None)
        if not dependency:
            code_total += 1
            code_hits += group == "vuln"
        if group == "vuln":
            hits += 1
            found.setdefault(label["id"], []).append(f)
            best_cwe[label["id"]] = max(best_cwe.get(label["id"], 0), level)
        elif group == "decoy":
            decoy_hits.setdefault(label["id"], []).append(f)
        else:
            other.append(f)

    recall = len(found) / len(vulns) if vulns else 0.0
    precision = hits / len(findings) if findings else 0.0
    code_precision = code_hits / code_total if code_total else 0.0
    missed = [v for v in vulns if v["id"] not in found]
    summary = {
        "label": name, "strict": args.strict, "n_findings": len(findings), "n_vuln": len(vulns),
        "detected": len(found), "recall": round(recall, 3),
        "cwe_exact": sum(v == 2 for v in best_cwe.values()), "cwe_related": sum(v >= 1 for v in best_cwe.values()),
        "tp_findings": hits, "precision": round(precision, 3), "code_precision": round(code_precision, 3),
        "decoys_flagged": sorted(decoy_hits), "decoy_findings": sum(len(v) for v in decoy_hits.values()),
        "other": len(other), "real_unlabelled": real_unlabelled, "hand": args.hand, "missed": [v["id"] for v in missed], "detected_ids": sorted(found),
    }

    print(f"\n=== {name}{' (strict)' if args.strict else ''}{' (hand-checked)' if args.hand else ''} ===")
    print(f"found:     {len(found)}/{len(vulns)} vulnerabilities ({recall:.0%}), "
          f"correct CWE {summary['cwe_exact']} exact / {summary['cwe_related']} incl. related")
    print(f"precision: {hits}/{len(findings)} findings on a real bug ({precision:.0%}); "
          f"code only {code_hits}/{code_total} ({code_precision:.0%})")
    print(f"decoys:    {len(decoy_hits)}/{len(decoys)} flagged; other/unlabelled findings: {len(other)}"
          + (f"; real but not in the answer key: {real_unlabelled}" if args.hand else ""))
    for v in missed:
        print(f"  MISSED  {v['id']} {v['cwe']:<9} [{v['category']}] {v['title']}")
    for did in sorted(decoy_hits):
        print(f"  DECOY   {did} {next(d for d in decoys if d['id'] == did)['title']}")
    for f in other:
        print(f"  OTHER   {f.get('tool', '?'):<9} {f.get('file')}:{f.get('line')}  {f.get('cwe')}  {str(f.get('title', ''))[:60]}")
    out = Path(args.findings[0]).parent / f"{name}{'_strict' if args.strict else ''}{'_hand' if args.hand else ''}_score.json"
    out.write_text(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
