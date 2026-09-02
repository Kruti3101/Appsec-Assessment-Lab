# Web and Mobile AppSec Assessment Lab

A structured workflow for finding, rating, tracking, and reporting application
security vulnerabilities — applied to deliberately vulnerable web and Android
applications running in a local lab.

The interesting part of application security is not finding a bug in a training
app. It is everything after: rating it defensibly, explaining it to a developer
who has to fix it, and proving it stayed fixed. This repository is built around
that half of the work.

## What's here

```
methodology/     Testing approach, aligned to OWASP WSTG and MASVS
findings/        One markdown file per finding, with YAML front matter
tools/           CVSS scoring, findings tracker, report generator
lab-setup/       Docker compose for lab targets, emulator and proxy setup
reports/         Generated output (git-ignored except examples)
evidence/        Screenshots referenced by findings
```

## The workflow

**1. Test against a lab target.** Follow the methodology in
`methodology/01-web-testing.md` or `02-mobile-testing.md` so coverage is
systematic rather than opportunistic.

**2. Write the finding.** Copy `findings/TEMPLATE.md`, fill in the front matter
and the write-up. `findings/EXAMPLE-001-reflected-xss.md` shows the expected
level of detail.

**3. Rate it.** Score the CVSS v3.1 vector:

```bash
python tools/cvss.py "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
# 6.1 (Medium)
```

**4. Triage.** List everything by risk, highest first:

```bash
python tools/track.py list
python tools/track.py list --status open
```

**5. Push to a tracker.** Export findings as tickets a developer can act on:

```bash
python tools/track.py export --format jira --out reports/jira-import.csv
```

**6. Report.** Generate a summary with risk breakdown and remediation status:

```bash
python tools/report.py --out reports/assessment-report.md
```

## The tooling

**`tools/cvss.py`** — CVSS v3.1 base score calculator implementing the FIRST
specification equations, including the spec's `roundup` behaviour, which plain
rounding gets wrong. Validated against published reference vectors.

**`tools/track.py`** — Parses every finding's front matter, validates required
fields and status values, scores each one, and sorts by risk. Exports to JSON,
CSV, or Jira-importable CSV. A malformed finding is reported and skipped rather
than silently dropped.

**`tools/report.py`** — Builds a single markdown assessment report: risk
summary, remediation status table, and full detail per finding.

## Scope and ethics

Every target in this lab is an application designed to be attacked, running on
infrastructure I control, bound to localhost.

Testing systems you do not own or have written authorization to test is
unlawful in most jurisdictions. Nothing here should be pointed at a third-party
host.

Findings describe the *condition* that makes a vulnerability exploitable and
the evidence confirming it, rather than shipping working exploit chains. That
is a deliberate choice: it is what a developer needs in order to fix the issue,
and it is how findings are written in professional assessments.

## Requirements

- Python 3.10+ and `pyyaml` (`pip install pyyaml`)
- Docker and Docker Compose for the web targets
- Android Studio and Burp Suite Community for the mobile targets

## References

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP MASVS](https://mas.owasp.org/MASVS/) and [MASTG](https://mas.owasp.org/MASTG/)
- [CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
