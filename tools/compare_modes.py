"""Compare the two confirmation modes on the same rules: hand-written replay vs the agent (investigate)."""
import json
from collections import Counter
from pathlib import Path


def load(path):
    if not Path(path).exists():
        return {}
    return {(e["route"], e["rule_type"], e["rule"]): e for e in json.loads(Path(path).read_text())}


def main():
    replay = load("runs/replay_log.json")
    agent = load("runs/investigate_log.json")
    keys = sorted(set(replay) | set(agent))
    if not keys:
        print("no logs found -- run replay.py and investigate.py first")
        return

    rows = [(k, replay.get(k, {}).get("verdict", "-"), agent.get(k, {}).get("verdict", "-")) for k in keys]
    agree = sum(r == a for _, r, a in rows)
    rc, ac = Counter(r for _, r, _ in rows), Counter(a for _, _, a in rows)

    print(f"\n=== replay vs agent on {len(keys)} rules ===\n")
    print(f"{'verdict':<14}{'replay':>8}{'agent':>8}")
    for v in sorted(set(rc) | set(ac)):
        print(f"{v:<14}{rc.get(v, 0):>8}{ac.get(v, 0):>8}")
    print(f"\nagree on {agree}/{len(keys)} rules, disagree on {len(keys) - agree}")

    both = sum(1 for _, r, a in rows if r == "confirmed" and a == "confirmed")
    ronly = [(k, r, a) for k, r, a in rows if r == "confirmed" and a != "confirmed"]
    aonly = [(k, r, a) for k, r, a in rows if a == "confirmed" and r != "confirmed"]
    invalid = [k for k, _, a in rows if a == "plan_invalid"]
    print(f"\nconfirmed by both:          {both}")
    print(f"confirmed only by replay:   {len(ronly)}  (agent did not reproduce)")
    print(f"confirmed only by agent:    {len(aonly)}  (replay did not reproduce)")
    if invalid:
        print(f"agent could not design a valid test for {len(invalid)} rules (not a 'safe' verdict)")

    def show(title, items):
        if not items:
            return
        print(f"\n{title}:")
        for (route, rt, rule), r, a in items:
            print(f"  {route}  [{rt}]")
            print(f"    replay = {r}: {replay.get((route, rt, rule), {}).get('why', '')[:88]}")
            print(f"    agent  = {a}: {agent.get((route, rt, rule), {}).get('why', '')[:88]}")

    show("confirmed only by replay (the agent missed these)", ronly)
    show("confirmed only by the agent (replay missed these)", aonly)
    print("\nfor correctness (which confirmations are real), run:")
    print("  python3 ../tools/score.py runs/replay.json")
    print("  python3 ../tools/score.py runs/investigate.json")


if __name__ == "__main__":
    main()
