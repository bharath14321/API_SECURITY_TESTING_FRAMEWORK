"""API3:2023 Broken object property level authorization - mass
assignment tester. Tries to set a privileged field (e.g. is_admin)
through a normal write endpoint."""
from scanner.findings import Finding


class MassAssignmentTester:
    def __init__(self, base_url, session, endpoint_template, resource_id, sensitive_fields=None):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.endpoint_template = endpoint_template
        self.resource_id = resource_id
        self.sensitive_fields = sensitive_fields or {"is_admin": True}

    def run(self):
        url = f"{self.base_url}{self.endpoint_template.format(id=self.resource_id)}"
        resp = self.session.patch(url, json=self.sensitive_fields)
        if resp.status_code != 200:
            return []
        try:
            body = resp.json()
        except ValueError:
            return []
        for field_name, expected_value in self.sensitive_fields.items():
            if body.get(field_name) == expected_value:
                return [Finding(
                    severity="CRITICAL",
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    endpoint=url,
                    title="Mass assignment of privileged field",
                    evidence=(
                        f"A PATCH request set '{field_name}' to "
                        f"{expected_value!r} even though this field "
                        f"should not be client-writable."
                    ),
                )]
        return []
