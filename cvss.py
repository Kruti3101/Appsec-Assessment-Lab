"""CVSS v3.1 base score calculator.

Implements the base metric equations from the FIRST CVSS v3.1 specification
(https://www.first.org/cvss/v3.1/specification-document).

Usage:
    python tools/cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    python tools/cvss.py AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
"""

from __future__ import annotations

import math
import sys

# Metric weights, per CVSS v3.1 section 7.4.
ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
# Privileges Required weights depend on Scope.
PRIVILEGES_REQUIRED = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
USER_INTERACTION = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


class CvssError(ValueError):
    """Raised when a vector string cannot be parsed."""


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.1 vector string into a metric dictionary."""
    parts = [p for p in vector.strip().split("/") if p]
    if parts and parts[0].upper().startswith("CVSS:"):
        parts = parts[1:]

    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise CvssError(f"Malformed metric {part!r} in vector")
        key, _, value = part.partition(":")
        metrics[key.strip().upper()] = value.strip().upper()

    missing = [m for m in METRIC_ORDER if m not in metrics]
    if missing:
        raise CvssError(f"Vector is missing required metrics: {', '.join(missing)}")
    return metrics


def roundup(value: float) -> float:
    """Round up to one decimal place, per the CVSS v3.1 Appendix A definition.

    Plain round() is not equivalent: the spec requires the smallest number to
    one decimal place that is greater than or equal to the input, computed on
    an integer representation to avoid float representation errors.
    """
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Return the CVSS v3.1 base score for a vector string."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    try:
        av = ATTACK_VECTOR[m["AV"]]
        ac = ATTACK_COMPLEXITY[m["AC"]]
        pr = PRIVILEGES_REQUIRED["C" if scope_changed else "U"][m["PR"]]
        ui = USER_INTERACTION[m["UI"]]
        conf, integ, avail = CIA[m["C"]], CIA[m["I"]], CIA[m["A"]]
    except KeyError as exc:
        raise CvssError(f"Unrecognised metric value: {exc}") from exc

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08

    return roundup(min(raw, 10.0))


def severity(score: float) -> str:
    """Map a base score to a qualitative severity rating (CVSS v3.1 section 5)."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    try:
        score = base_score(argv[1])
    except CvssError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{score} ({severity(score)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
