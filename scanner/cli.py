"""
Entry point:  python -m scanner.cli --target http://localhost:5000 [options]

Runs the full module suite + OpenAPI-driven fuzzer against a target,
generates an HTML (and optionally PDF) report, and exits non-zero if
any finding at or above --fail-on severity was found. That exit code
is what turns this into a CI/CD security gate (see
.github/workflows/security-scan.yml).
"""
import argparse
import json
import sys

import requests

from scanner.findings import Finding, SEVERITY_ORDER
from scanner.fuzzer.openapi_fuzzer import OpenAPIFuzzer
from scanner.modules.bola_tester import BOLATester
from scanner.modules.jwt_attacks import JWTAttackSuite
from scanner.modules.mass_assignment_tester import MassAssignmentTester
from scanner.modules.rate_limit_tester import RateLimitTester
from scanner.modules.secrets_scanner import SecretsScanner
from scanner.modules.security_headers import SecurityHeadersChecker
from scanner.report_generator import ReportGenerator


def login(base_url, username, password):
    resp = requests.post(f"{base_url}/api/login", json={"username": username, "password": password}, timeout=10)
    resp.raise_for_status()
    return resp.json()["token"]


def make_session(token):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}"})
    return s


def run_scan(base_url, known_secret=None):
    all_findings = []

    token_a = login(base_url, "alice", "alicepassword")
    token_b = login(base_url, "bob", "bobpassword")

    session_a = make_session(token_a)
    session_b = make_session(token_b)

    print("[*] Running BOLA tests...")
    bola = BOLATester(base_url, session_a, session_b, user_a_id=1)
    all_findings += bola.run([
        ("/api/orders/{id}", 101),
        ("/api/accounts/{id}", 1),
    ])

    print("[*] Running JWT attack suite...")
    jwt_suite = JWTAttackSuite(base_url, "/api/accounts/1", token_a, requests.Session(), known_secret=known_secret)
    all_findings += jwt_suite.run()

    print("[*] Running rate-limit tests...")
    rate_tester = RateLimitTester(
        base_url, "/api/login", method="POST",
        json_body={"username": "alice", "password": "wrong-password"},
    )
    all_findings += rate_tester.run()

    print("[*] Running mass-assignment test...")
    mass_assign = MassAssignmentTester(base_url, session_a, "/api/users/{id}", 1)
    all_findings += mass_assign.run()

    print("[*] Checking function-level authorization on /admin/users...")
    resp = session_a.get(f"{base_url}/admin/users")
    if resp.status_code == 200:
        all_findings.append(Finding(
            severity="CRITICAL",
            owasp="API5:2023 Broken Function Level Authorization",
            endpoint=f"{base_url}/admin/users",
            title="Non-admin user accessed admin endpoint",
            evidence="A regular authenticated user retrieved /admin/users (status 200).",
        ))

    print("[*] Checking security headers and scanning for exposed secrets...")
    sample_endpoints = ["/api/accounts/1", "/api/orders/101", "/health"]
    all_findings += SecurityHeadersChecker(base_url, session_a, sample_endpoints).run()
    all_findings += SecretsScanner(base_url, session_a, sample_endpoints).run()

    print("[*] Running OpenAPI-driven fuzzer...")
    spec = requests.get(f"{base_url}/openapi.json", timeout=10).json()
    fuzzer = OpenAPIFuzzer(
        base_url, spec, session_a, session_b, user_a_id=1,
        sample_resource_ids={
            "/api/orders/{order_id}": 101,
            "/api/accounts/{account_id}": 1,
            "/api/users/{user_id}": 1,
        },
    )
    all_findings += fuzzer.generate_and_run()

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="OWASP API Security Top 10 (2023) scanner")
    parser.add_argument("--target", required=True, help="Base URL of the target API, e.g. http://localhost:5000")
    parser.add_argument("--output", default="reports/report.html", help="Path to write the HTML report")
    parser.add_argument("--pdf", action="store_true", help="Also render a PDF report (requires weasyprint)")
    parser.add_argument("--known-secret", default=None, help="JWT signing secret (white-box/CI mode only)")
    parser.add_argument(
        "--fail-on", default="CRITICAL",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        help="Exit non-zero if any finding at or above this severity is present (used as the CI gate)",
    )
    args = parser.parse_args()

    print(f"Scanning {args.target} ...")
    findings = run_scan(args.target, known_secret=args.known_secret)

    report = ReportGenerator(findings, target_url=args.target)
    html_path = report.render_html(args.output)
    print(f"\nReport written to {html_path}")

    if args.pdf:
        pdf_path = args.output.rsplit(".", 1)[0] + ".pdf"
        report.render_pdf(html_path, pdf_path)

    summary = report.summary()
    print(json.dumps(summary, indent=2))

    if args.fail_on != "NONE":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in findings):
            print(f"\nFAIL: findings at or above {args.fail_on} severity were found.")
            sys.exit(1)

    print("\nPASS: no findings at or above the failure threshold.")
    sys.exit(0)


if __name__ == "__main__":
    main()
