"""Phase 4 - OpenAPI-driven test generation.

Reads the target's openapi.json and auto-generates test cases per
endpoint instead of hardcoding them per route:
  - for every auth-required endpoint: a no-auth request
  - for every GET with a path parameter (and a known sample resource
    ID): a cross-user BOLA request
  - for every PATCH whose schema has a field that looks privileged
    (name contains "admin"/"role"/"privileg"): a mass-assignment request

This is what separates "a folder of hardcoded test scripts" from "a
scanner" - point it at a different OpenAPI spec and it generates a
different set of test cases automatically.

Note: discovering which resource IDs belong to which user is itself a
black-box problem. In a fully automated crawler you'd discover these by
first calling the API as user A. Here we accept a small
sample_resource_ids map to keep the example focused on the fuzzing
logic itself.
"""
import re

import requests

from scanner.findings import Finding
from scanner.modules.bola_tester import BOLATester
from scanner.modules.mass_assignment_tester import MassAssignmentTester

WRITE_METHODS = ("post", "put", "patch", "delete")
ALL_METHODS = ("get",) + WRITE_METHODS
PRIVILEGED_FIELD_HINTS = ("admin", "role", "privileg")


class OpenAPIFuzzer:
    def __init__(self, base_url, spec, session_a, session_b, user_a_id, sample_resource_ids=None):
        self.base_url = base_url.rstrip("/")
        self.spec = spec
        self.session_a = session_a
        self.session_b = session_b
        self.user_a_id = user_a_id
        self.sample_resource_ids = sample_resource_ids or {}

    @staticmethod
    def _requires_auth(operation):
        return bool(operation.get("security"))

    @staticmethod
    def _path_params(path_item, operation):
        params = operation.get("parameters", []) or path_item.get("parameters", [])
        return [p for p in params if p.get("in") == "path"]

    @staticmethod
    def _writable_fields(operation):
        schema = (
            operation.get("requestBody", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        return list(schema.get("properties", {}).keys())

    def _test_no_auth(self, path, method):
        url_path = re.sub(r"\{[^}]+\}", "1", path)
        url = f"{self.base_url}{url_path}"
        anon = requests.Session()
        try:
            resp = anon.request(method, url, timeout=10)
        except requests.RequestException:
            return []
        if resp.status_code == 200:
            return [Finding(
                severity="HIGH",
                owasp="API2:2023 Broken Authentication",
                endpoint=url,
                title="Endpoint accessible without authentication",
                evidence=f"{method.upper()} {url} returned 200 with no Authorization header.",
            )]
        return []

    def generate_and_run(self):
        findings = []
        bola = BOLATester(self.base_url, self.session_a, self.session_b, self.user_a_id)

        for path, path_item in self.spec.get("paths", {}).items():
            for method, operation in path_item.items():
                if method not in ALL_METHODS:
                    continue

                if self._requires_auth(operation):
                    findings.extend(self._test_no_auth(path, method))

                path_params = self._path_params(path_item, operation)

                if method == "get" and path_params and path in self.sample_resource_ids:
                    param_name = path_params[0]["name"]
                    template = path.replace("{" + param_name + "}", "{id}")
                    finding = bola.test_endpoint(template, self.sample_resource_ids[path])
                    if finding:
                        findings.append(finding)

                if method == "patch" and path_params and path in self.sample_resource_ids:
                    writable = self._writable_fields(operation)
                    privileged = [
                        f for f in writable
                        if any(hint in f.lower() for hint in PRIVILEGED_FIELD_HINTS)
                    ]
                    if privileged:
                        param_name = path_params[0]["name"]
                        template = path.replace("{" + param_name + "}", "{id}")
                        tester = MassAssignmentTester(
                            self.base_url,
                            self.session_a,
                            template,
                            self.sample_resource_ids[path],
                            sensitive_fields={f: True for f in privileged},
                        )
                        findings.extend(tester.run())

        return findings
