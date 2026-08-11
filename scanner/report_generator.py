"""Aggregates Finding objects into an HTML (and optional PDF) report
with CVSS-style severity scoring and remediation guidance."""
import os
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.findings import SEVERITY_ORDER

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

# Simple hardcoded severity -> CVSS-ish score table, not a full CVSS
# calculator (that's out of scope here, and a real calculator needs
# the full vector, not just a severity label).
SEVERITY_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.0}


class ReportGenerator:
    def __init__(self, findings, target_url, vulnerable_mode=None):
        self.findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
        self.target_url = target_url
        self.vulnerable_mode = vulnerable_mode
        self.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def summary(self):
        by_severity = {}
        by_owasp = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_owasp[f.owasp] = by_owasp.get(f.owasp, 0) + 1
        return {
            "total": len(self.findings),
            "by_severity": by_severity,
            "by_owasp": by_owasp,
            "critical_count": by_severity.get("CRITICAL", 0),
        }

    def render_html(self, output_path):
        env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html"]),
        )
        template = env.get_template("report_template.html")
        html = template.render(
            findings=self.findings,
            summary=self.summary(),
            target_url=self.target_url,
            vulnerable_mode=self.vulnerable_mode,
            generated_at=self.generated_at,
            severity_score=SEVERITY_SCORE,
        )
        out_dir = os.path.dirname(output_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(html)
        return output_path

    def render_pdf(self, html_path, pdf_path):
        """Optional. Requires: pip install weasyprint, plus system libs
        (Cairo, Pango, GDK-PixBuf - see README). Fails gracefully if not
        installed so the HTML report always works regardless."""
        try:
            from weasyprint import HTML
        except ImportError:
            print(
                "[report] weasyprint not installed (or its system "
                "dependencies are missing) - skipping PDF export. The "
                "HTML report is still available. See README for install "
                "instructions."
            )
            return None
        HTML(html_path).write_pdf(pdf_path)
        return pdf_path
