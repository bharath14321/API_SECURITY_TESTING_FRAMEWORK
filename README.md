# API Security Testing Framework

An automated scanner for the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/),
built against a deliberately vulnerable target API that can be flipped
between an **insecure** and a **hardened** configuration with a single
environment variable. That toggle is what lets this project tell a
complete story: seed real vulnerabilities → scan finds them → fix the
code → scan confirms clean → wire the scan into CI so it never
regresses.

> **Ethics & legality:** this framework is for testing systems you own
> or are explicitly authorized to test. Only ever point it at the
> local `target-api` container included here — never at third-party
> production systems.

---

## What's in here

| Component | What it does |
|---|---|
| `target_api/` | A small Flask "banking/e-commerce" API (`/accounts`, `/orders`, `/admin`) with `VULNERABLE_MODE` seeding real OWASP API1, API2, API3, API4, API5, and API8 findings, and the correct fix on the same routes |
| `scanner/modules/` | Independent, pluggable test modules: BOLA, JWT attacks, rate-limit/flood + header-spoof bypass, mass assignment, security headers, secrets/entropy scanning |
| `scanner/fuzzer/` | Reads the target's `openapi.json` and **auto-generates** no-auth / BOLA / mass-assignment test cases per endpoint, instead of hardcoding them |
| `scanner/report_generator.py` | Aggregates findings into a severity-scored HTML report (+ optional PDF) with remediation text |
| `scanner/zap_integration.py` | Optional OWASP ZAP active-scan integration (requires a ZAP daemon — not started by default) |
| `.github/workflows/security-scan.yml` | CI gate: runs the scanner on every PR and fails the build on CRITICAL findings |
| `docker-compose.yml` | One command to run target API + scanner together |

---

## Architecture

```
┌─────────────────────┐        ┌──────────────────────────┐
│  Target API          │◄──────►│   Scanner Core             │
│  (Flask)              │  HTTP  │  - BOLA tester             │
│  VULNERABLE_MODE=1/0  │        │  - JWT attack suite        │
└─────────────────────┘        │  - Rate-limit tester       │
                                │  - Mass-assignment tester  │
                                │  - Security headers        │
                                │  - Secrets/entropy scanner │
                                │  - OpenAPI fuzzer           │
                                └──────────┬────────────────┘
                                           ▼
                                  ┌─────────────────┐
                                  │  HTML/PDF Report │
                                  │  (CVSS-scored)   │
                                  └────────┬─────────┘
                                           ▼
                                  ┌─────────────────┐
                                  │  CI/CD gate       │
                                  │  (GitHub Actions) │
                                  └─────────────────┘
```

---

## Quick start (Docker — recommended)

```bash
git clone <your-fork-url>
cd api-security-framework
docker-compose up --build
```

This starts the target API in vulnerable mode and runs the scanner
against it, writing `reports/report.html`. Open that file in a
browser to see the results.

To see the CI gate actually fail (as it would in a PR check):

```bash
docker-compose run scanner --target http://target-api:5000 --output reports/report.html --fail-on CRITICAL
```

To demo the fix, restart the target in secure mode and re-scan:

```bash
VULNERABLE_MODE=false docker-compose up --build target-api
docker-compose run scanner --target http://target-api:5000 --output reports/report_secure.html --fail-on CRITICAL
```

---

## Quick start (local, no Docker)

```bash
python3 -m venv .venv && source .venv/bin/activate

# terminal 1 - target API
pip install -r target_api/requirements.txt
VULNERABLE_MODE=true python target_api/app.py

# terminal 2 - scanner
pip install -r scanner/requirements.txt
python -m scanner.cli --target http://localhost:5000 --output reports/report.html
```

Seeded test users: `alice` / `alicepassword`, `bob` / `bobpassword`,
`admin` / `adminpassword` (see `target_api/models.py`).

---

## OWASP API Security Top 10 (2023) coverage

| Category | Seeded in `target_api` | Detected by |
|---|---|---|
| API1 — Broken Object Level Authorization | `/api/orders/<id>`, `/api/accounts/<id>` skip ownership checks | `bola_tester.py`, OpenAPI fuzzer |
| API2 — Broken Authentication | accepts `alg=none` JWTs; accepts tokens with an empty signature segment; weak hardcoded signing secret | `jwt_attacks.py` |
| API3 — Broken Object Property Level Authorization | `PATCH /api/users/<id>` binds every field, incl. `is_admin` | `mass_assignment_tester.py`, OpenAPI fuzzer |
| API4 — Unrestricted Resource Consumption | `/api/login` has no rate limiting | `rate_limit_tester.py` |
| API5 — Broken Function Level Authorization | `/admin/users` has no server-side role check | `cli.py` (function-level check) |
| API8 — Security Misconfiguration | debug mode on, missing security headers | `security_headers.py` |
| — Secrets Exposure (cross-cutting) | — | `secrets_scanner.py` (regex + Shannon entropy) |

Flip `VULNERABLE_MODE=false` and every one of these is fixed on the
same routes — see `target_api/app.py`, it's commented at each
decision point.

---

## Running the test suite

```bash
pip install -r scanner/requirements.txt
python -m pytest tests/ -v
```

The tests spin up the target API in-process and run real scanner
modules against it — they're integration tests, not mocks.

> **If tests fail unexpectedly:** the fixture in `tests/conftest.py`
> binds to port 5050. If a previous run's server is still bound to
> that port (e.g. you `Ctrl-C`'d a hung test), new tests will silently
> talk to the *old* process instead of a fresh one, which can produce
> confusing failures like a BOLA test finding nothing. Check with
> `lsof -i :5050` and kill any stale process before re-running.

---

## Demo script (for interviews / a Loom recording)

1. `docker-compose up --build` with `VULNERABLE_MODE=true` — show the
   report: multiple CRITICAL findings across API1/2/3/5.
2. Open `target_api/app.py`, point at the `if not VULNERABLE_MODE:`
   branches — explain the fix for each.
3. Flip to `VULNERABLE_MODE=false`, re-run the scan — report is clean,
   exit code 0.
4. Show `.github/workflows/security-scan.yml` — this is the same scan
   gating every PR in CI.

This is the single most effective narrative for a technical
interview: it shows you understand *why* something is vulnerable, not
just that a tool printed red text.

---

## Development notes: closing a detection gap

While validating the JWT attack suite, `jwt_attacks.py`'s
`test_missing_signature_verification()` never returned a finding
against the target, in either mode. Root cause: `decode_token()` in
`target_api/app.py` only skipped signature verification when the
token's header explicitly said `"alg": "none"` — a token with a
normal `HS256` header but an *empty* signature segment still went
through `jwt.decode(...)`, which correctly rejected it. The scanner
module was checking for a bug the target didn't actually have.

Fix: `decode_token()` now also skips verification when the signature
segment is empty, regardless of the declared algorithm — a realistic
bug class (custom decode logic that special-cases "no signature"
without truly requiring one). Re-running the scanner after the fix
shows the finding count go from 13 (9 CRITICAL) to 14 (10 CRITICAL) in
vulnerable mode, while secure mode still returns 0 findings — the fix
is correctly scoped to `VULNERABLE_MODE` only.

---

## Extending this project

These are genuinely valuable but intentionally left as v2 to keep the
core buildable in a reasonable amount of time:

- **OWASP ZAP integration** — `scanner/zap_integration.py` has a
  working client; wire it into `cli.py` once you have a ZAP daemon
  running (`docker run -p 8080:8080 owasp/zap2docker-stable zap.sh
  -daemon ...`).
- **PDF export** — `pip install weasyprint` (needs system libs: on
  Debian/Ubuntu, `apt-get install libpango-1.0-0 libpangocairo-1.0-0
  libgdk-pixbuf2.0-0`), then pass `--pdf` to `scanner.cli`.
- **Dashboard** — a Flask+Chart.js or React+Recharts page over a
  `reports/history.jsonl` file (append each scan's `summary()` output)
  gives you a trend chart with very little code.
- **Slack/email alerts** — call a webhook from `cli.py` when
  `summary()["critical_count"] > 0`.
- **Git-history secrets scanning** — run `secrets_scanner.py`'s regex
  patterns over `git log -p` output, not just live HTTP responses.
- **Postgres** — swap `target_api/models.py`'s `InMemoryDB` for
  SQLAlchemy; there's a commented-out Postgres service in
  `docker-compose.yml` to get started.

---

## Repo structure

```
api-security-framework/
├── target_api/
│   ├── app.py              # VULNERABLE_MODE toggle, all routes
│   ├── models.py            # in-memory data layer
│   ├── openapi.json          # spec consumed by the fuzzer
│   ├── requirements.txt
│   └── Dockerfile
├── scanner/
│   ├── cli.py                        # entry point / CI gate
│   ├── findings.py                    # Finding model + remediation text
│   ├── report_generator.py            # HTML/PDF report
│   ├── zap_integration.py             # optional ZAP client
│   ├── modules/
│   │   ├── bola_tester.py
│   │   ├── jwt_attacks.py
│   │   ├── rate_limit_tester.py
│   │   ├── mass_assignment_tester.py
│   │   ├── security_headers.py
│   │   └── secrets_scanner.py
│   ├── fuzzer/
│   │   └── openapi_fuzzer.py
│   ├── templates/
│   │   └── report_template.html
│   ├── requirements.txt
│   └── Dockerfile
├── tests/                    # pytest, integration-style
├── reports/                    # generated reports land here
├── .github/workflows/security-scan.yml
├── docker-compose.yml
└── README.md
```
