---
title: Run in CI
parent: User guide
nav_order: 7
---

# Run in CI
{: .no_toc }

Groot is built for CI: it needs no credentials for scanning, it exits with a clear code, and it writes formats CI systems understand.

1. TOC
{:toc}

---

## Exit codes

Every Groot command uses the same exit codes, so your CI can rely on them:

| Code | Meaning | What your CI should do |
| --- | --- | --- |
| `0` | Nothing wrong was found. | Pass |
| `1` | Groot found a problem: a failed test scenario, or a scan finding at or above `--fail-on`. | Fail the build |
| `2` | Groot couldn't run: a bad flag, a missing file, an invalid suite or policy. | Fail the build, and fix the setup |

Inconclusive test scenarios don't fail the build unless you add `--strict`.

## GitHub Actions

The repository is also a GitHub Action. It builds Groot, runs your suite, scans a folder, and uploads everything.

```yaml
name: groot
on: [pull_request]

permissions:
  contents: read
  security-events: write   # to upload scan findings to code scanning

jobs:
  groot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ...set up and start whatever your agent's tests need...
      - uses: mohitkumar/groot@main
        with:
          suite: groot-suite.json
          path: .
          fail-on: critical
```

| Input | Default | Meaning |
| --- | --- | --- |
| `suite` | (none) | Your test suite. If set, the job fails when any scenario fails. Leave it empty to only scan. |
| `path` | `.` | The folder to scan. Put your Kubernetes and AWS exports here. |
| `fail-on` | `critical` | Fail on scan findings at this severity or above: `critical`, `high`, `medium`, `low` or `none`. |
| `upload-sarif` | `true` | Upload scan findings to GitHub code scanning. Needs `security-events: write`. |

What you get:

- **On the job's summary page:** the test progress and the scan in text form.
- **Artifacts:** `groot-test-evidence` (the JUnit file, the HTML test report, and every scenario's evidence folder) and `groot-reach-report` (the HTML reach report).
- **In pull requests:** scan findings as code scanning alerts, linked to the agent's files.

### Getting the exports into CI

The scan needs your Kubernetes and AWS exports in the scanned folder. Common approaches:

- **Export in the job**, with a read-only role:

  ```yaml
  - name: Export permissions
    run: |
      mkdir -p scan
      kubectl get deploy,sts,ds,cronjob,job,sa,role,clusterrole,rolebinding,clusterrolebinding -A -o json > scan/k8s.json
      aws iam get-account-authorization-details --output json > scan/iam.json
  ```

- **Export on a schedule** in a separate, more trusted job, and download the files as an artifact in the pull-request job. This keeps cloud credentials out of pull-request workflows.

## Any other CI

Groot is a single binary, so it works anywhere. A typical job:

```bash
# Build (or download a binary you built earlier)
go build -o groot ./cmd/groot

# Test: JUnit for the CI's test view, HTML for people
./groot test --suite groot-suite.json --format junit --html groot-report.html > groot-junit.xml

# Scan: fail on critical findings, keep a visual report
./groot scan --fail-on critical .
./groot graph . > groot-reach.html
```

Then publish `groot-junit.xml` as a test report, and keep `groot-report.html`, `groot-reach.html` and the `.groot/runs/` folder as artifacts.

### GitLab CI example

```yaml
groot:
  image: golang:1.24
  script:
    - go build -o groot ./cmd/groot
    - ./groot test --suite groot-suite.json --format junit --html groot-report.html > groot-junit.xml
    - ./groot scan --fail-on critical .
  after_script:
    - ./groot graph . > groot-reach.html || true
  artifacts:
    when: always
    reports:
      junit: groot-junit.xml
    paths:
      - groot-report.html
      - groot-reach.html
      - .groot/runs/
```

## Recommendations

- **Run tests against a test environment.** Groot passes allowed calls through to your real tool servers.
- **Run attack scenarios more than once,** for example nightly as well as on pull requests. AI agents don't behave identically every run.
- **Start with `--fail-on critical`** for the scan, and tighten it once the critical findings are fixed.
- **Validate your policy** in the same job with `groot policy check groot-policy.json`.
- **Keep the evidence.** When a scenario fails, the audit log and agent output in the evidence folder show exactly what happened.
