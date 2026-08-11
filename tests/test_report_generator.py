"""Unit test: report generator, no network required."""
from scanner.findings import Finding
from scanner.report_generator import ReportGenerator


def test_report_summary_and_render(tmp_path):
    findings = [
        Finding(severity="CRITICAL", owasp="API1:2023 BOLA", endpoint="/api/orders/1", evidence="test"),
        Finding(severity="LOW", owasp="API8:2023 Security Misconfiguration", endpoint="/health", evidence="test"),
    ]
    report = ReportGenerator(findings, target_url="http://localhost:5000")
    summary = report.summary()
    assert summary["total"] == 2
    assert summary["critical_count"] == 1

    output_path = tmp_path / "report.html"
    report.render_html(str(output_path))
    assert output_path.exists()

    content = output_path.read_text()
    assert "API1:2023 BOLA" in content
    assert "No findings" not in content
