"""Turn the output of bandit, semgrep, pip-audit and gitleaks (raw/*.json) into one list: findings.json."""
import json
from pathlib import Path

SEVERITY = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "info": "LOW", "warning": "MEDIUM", "error": "HIGH"}


def finding(tool, rule_id, title, file, line, snippet, severity, cwe, extra):
    return {"tool": tool, "rule_id": rule_id, "title": title, "file": file, "line": line,
            "snippet": snippet, "severity": severity, "cwe": cwe, "extra": extra}


def relative(path):
    if not path:
        return None
    try:
        return str(Path(path).resolve().relative_to(Path(".").resolve()))
    except ValueError:
        return str(path)


def from_bandit(data):
    out = []
    for r in data.get("results", []):
        line = r.get("line_number")
        # bandit's "code" is a few lines that start with their line number; keep the flagged one
        code = next((raw[len(f"{line} "):].strip()[:200] for raw in (r.get("code") or "").splitlines()
                     if line is not None and raw.startswith(f"{line} ")), "")
        cwe = (r.get("issue_cwe") or {}).get("id")
        out.append(finding("bandit", r.get("test_id", ""), r.get("test_name") or r.get("issue_text", "")[:80],
                           relative(r.get("filename")), line, code,
                           SEVERITY.get(str(r.get("issue_severity")).lower(), "UNKNOWN"),
                           [f"CWE-{cwe}"] if cwe else [],
                           {"confidence": r.get("issue_confidence"), "text": r.get("issue_text")}))
    return out


def semgrep_code(r):
    """Semgrep without a login hides the code ("requires login"), so read the line from the file."""
    lines = (r.get("extra") or {}).get("lines") or ""
    if lines.strip() and lines.strip() != "requires login":
        return lines.strip()[:200]
    path, n = Path(r.get("path", "")), (r.get("start") or {}).get("line")
    if path.is_file() and n:
        src = path.read_text(errors="replace").splitlines()
        if 1 <= n <= len(src):
            return src[n - 1].strip()[:200]
    return ""


def from_semgrep(data):
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwes = meta.get("cwe", [])
        cwes = [cwes] if isinstance(cwes, str) else cwes
        cwe_ids = [c.split(":")[0].strip().upper() for c in cwes if c.split(":")[0].strip().upper().startswith("CWE-")]
        out.append(finding("semgrep", r.get("check_id", "").split(".")[-1],
                           (meta.get("shortDescription") or extra.get("message", ""))[:80],
                           relative(r.get("path")), (r.get("start") or {}).get("line"), semgrep_code(r),
                           SEVERITY.get(str(extra.get("severity")).lower(), "UNKNOWN"),
                           cwe_ids, {"message": extra.get("message", "")[:300], "owasp": meta.get("owasp")}))
    return out


def from_pip_audit(data):
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    out, seen = [], set()
    for dep in deps or []:
        name, version = dep.get("name"), dep.get("version")
        for v in dep.get("vulns", []) or []:
            if ((name or "").lower(), v.get("id")) in seen:      # pip-audit can list an advisory twice
                continue
            seen.add(((name or "").lower(), v.get("id")))
            cves = [i for i in [v.get("id")] + v.get("aliases", []) if i and i.startswith("CVE-")]
            out.append(finding("pip-audit", v.get("id", ""), f"{name} {version}: {(v.get('description') or '')[:60]}",
                               "requirements.txt", None, f"{name}=={version}", "UNKNOWN", ["CWE-1395"],
                               {"package": (name or "").lower(), "version": version, "cves": cves,
                                "fix_versions": v.get("fix_versions", [])}))
    return out


def from_gitleaks(data):
    out = []
    for r in data or []:
        secret = r.get("Secret") or ""
        hidden = secret[:4] + "…" if secret else ""
        match = (r.get("Match") or "").replace(secret, hidden) if secret else (r.get("Match") or "")
        out.append(finding("gitleaks", r.get("RuleID", ""), f"Secret: {r.get('Description', '')[:60]}",
                           relative(r.get("File")), r.get("StartLine"), match[:80], "HIGH", ["CWE-798"],
                           {"secret_redacted": hidden}))
    return out


SCANNERS = {"bandit": from_bandit, "semgrep": from_semgrep, "pip_audit": from_pip_audit, "gitleaks": from_gitleaks}


def main():
    findings = []
    for name, read in SCANNERS.items():
        path = Path(f"raw/{name}.json")
        if not path.exists():
            print(f"  {name:<10} skipped, no {path}")
            continue
        got = read(json.loads(path.read_text()))
        findings += got
        print(f"  {name:<10} {len(got)} findings")
    Path("findings.json").write_text(json.dumps(findings, indent=2))
    print(f"\n{len(findings)} findings -> findings.json")


if __name__ == "__main__":
    main()
