"""Findings tracker.

Reads the YAML front matter from every file in findings/, validates it, scores
it with the CVSS module, and exports the set as JSON, CSV, or a JIRA-importable
CSV. This is what turns a folder of markdown write-ups into something you can
triage, sort by risk, and track to closure.

Usage:
    python tools/track.py list
    python tools/track.py list --status open
    python tools/track.py export --format json --out reports/findings.json
    python tools/track.py export --format csv  --out reports/findings.csv
    python tools/track.py export --format jira --out reports/jira-import.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss import CvssError, base_score, severity  # noqa: E402

FINDINGS_DIR = Path(__file__).resolve().parent.parent / "findings"

REQUIRED_FIELDS = ["id", "title", "target", "category", "cvss_vector", "status"]
VALID_STATUS = {"open", "in-remediation", "retest", "closed", "risk-accepted"}

# Severity order for sorting: highest risk first.
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}


class FindingError(ValueError):
    """Raised when a finding file is malformed."""


def split_front_matter(text: str) -> tuple[dict, str]:
    """Split a markdown file into its YAML front matter and body."""
    if not text.startswith("---"):
        raise FindingError("file does not begin with '---' front matter")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise FindingError("front matter block is not closed with '---'")
    meta = yaml.safe_load(parts[1]) or {}
    if not isinstance(meta, dict):
        raise FindingError("front matter did not parse to a mapping")
    return meta, parts[2].strip()


def load_finding(path: Path) -> dict:
    """Load and validate a single finding file."""
    meta, body = split_front_matter(path.read_text(encoding="utf-8"))

    missing = [f for f in REQUIRED_FIELDS if f not in meta]
    if missing:
        raise FindingError(f"missing required field(s): {', '.join(missing)}")

    status = str(meta["status"]).lower()
    if status not in VALID_STATUS:
        raise FindingError(
            f"status {status!r} is not one of: {', '.join(sorted(VALID_STATUS))}"
        )

    try:
        score = base_score(str(meta["cvss_vector"]))
    except CvssError as exc:
        raise FindingError(f"bad cvss_vector: {exc}") from exc

    return {
        "id": str(meta["id"]),
        "title": str(meta["title"]),
        "target": str(meta["target"]),
        "category": str(meta["category"]),
        "cwe": str(meta.get("cwe", "")),
        "masvs": str(meta.get("masvs", "")),
        "wstg": str(meta.get("wstg", "")),
        "cvss_vector": str(meta["cvss_vector"]),
        "cvss_score": score,
        "severity": severity(score),
        "status": status,
        "found": str(meta.get("found", "")),
        "retested": str(meta.get("retested", "")),
        "file": path.name,
        "body": body,
    }


def load_all(findings_dir: Path = FINDINGS_DIR) -> list[dict]:
    """Load every finding, skipping the template. Sorted by risk, highest first."""
    findings, errors = [], []
    for path in sorted(findings_dir.glob("*.md")):
        if path.name.upper().startswith("TEMPLATE"):
            continue
        try:
            findings.append(load_finding(path))
        except FindingError as exc:
            errors.append(f"{path.name}: {exc}")

    if errors:
        for err in errors:
            print(f"warning: skipped {err}", file=sys.stderr)

    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], -f["cvss_score"]))
    return findings


def cmd_list(args: argparse.Namespace) -> int:
    findings = load_all()
    if args.status:
        findings = [f for f in findings if f["status"] == args.status]

    if not findings:
        print("No findings matched.")
        return 0

    print(f"{'ID':<10} {'SEVERITY':<9} {'SCORE':<6} {'STATUS':<15} TITLE")
    print("-" * 88)
    for f in findings:
        print(
            f"{f['id']:<10} {f['severity']:<9} {f['cvss_score']:<6} "
            f"{f['status']:<15} {f['title'][:38]}"
        )

    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join(
        f"{n} {sev}" for sev, n in sorted(counts.items(), key=lambda kv: SEVERITY_RANK[kv[0]])
    )
    print(f"\n{len(findings)} finding(s): {summary}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    findings = load_all()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    if args.format == "json":
        out.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    elif args.format == "csv":
        cols = [
            "id", "title", "target", "category", "cwe", "masvs", "wstg",
            "cvss_vector", "cvss_score", "severity", "status", "found", "retested",
        ]
        with out.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(findings)

    elif args.format == "jira":
        # Column names match Jira's default CSV importer fields.
        with out.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                ["Summary", "Issue Type", "Priority", "Labels", "Description"]
            )
            priority = {
                "Critical": "Highest",
                "High": "High",
                "Medium": "Medium",
                "Low": "Low",
                "None": "Lowest",
            }
            for f in findings:
                labels = " ".join(
                    x for x in ["appsec", f["category"].lower().replace(" ", "-"), f["cwe"]] if x
                )
                desc = (
                    f"Target: {f['target']}\n"
                    f"CVSS: {f['cvss_score']} ({f['severity']}) {f['cvss_vector']}\n"
                    f"Reference: {f['cwe']} {f['masvs']} {f['wstg']}\n\n"
                    f"{f['body']}"
                )
                writer.writerow(
                    [f"[{f['id']}] {f['title']}", "Bug",
                     priority[f["severity"]], labels, desc]
                )

    print(f"Wrote {len(findings)} finding(s) to {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Track and export AppSec findings.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="print findings sorted by risk")
    p_list.add_argument("--status", choices=sorted(VALID_STATUS))
    p_list.set_defaults(func=cmd_list)

    p_exp = sub.add_parser("export", help="export findings to a file")
    p_exp.add_argument("--format", choices=["json", "csv", "jira"], required=True)
    p_exp.add_argument("--out", required=True)
    p_exp.set_defaults(func=cmd_export)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
