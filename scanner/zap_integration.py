"""
Phase 6 (optional/stretch) - OWASP ZAP integration.

Not wired into cli.py by default, since it requires a running ZAP
daemon alongside the target. To use it:

    pip install python-owasp-zap-v2.4
    docker run -u zap -p 8080:8080 -d owasp/zap2docker-stable \\
        zap.sh -daemon -host 0.0.0.0 -port 8080 \\
        -config api.disablekey=true

Then in your own script:

    from scanner.zap_integration import ZAPScanner
    findings = ZAPScanner("http://localhost:5000").run_active_scan()
    # merge `findings` into the same list you pass to ReportGenerator
"""
import time

try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None

from scanner.findings import Finding

ZAP_RISK_TO_SEVERITY = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}


class ZAPScanner:
    def __init__(self, target_url, zap_proxy="http://127.0.0.1:8080"):
        if ZAPv2 is None:
            raise RuntimeError(
                "python-owasp-zap-v2.4 is not installed. Run "
                "`pip install python-owasp-zap-v2.4` and start a ZAP "
                "daemon before using ZAPScanner."
            )
        self.target_url = target_url
        self.zap = ZAPv2(proxies={"http": zap_proxy, "https": zap_proxy})

    def run_active_scan(self, poll_interval=5, timeout=600):
        self.zap.urlopen(self.target_url)
        scan_id = self.zap.ascan.scan(self.target_url)

        elapsed = 0
        while int(self.zap.ascan.status(scan_id)) < 100 and elapsed < timeout:
            time.sleep(poll_interval)
            elapsed += poll_interval

        findings = []
        for alert in self.zap.core.alerts(baseurl=self.target_url):
            findings.append(Finding(
                severity=ZAP_RISK_TO_SEVERITY.get(alert.get("risk"), "INFO"),
                owasp="ZAP: " + alert.get("alert", "Unknown"),
                endpoint=alert.get("url", self.target_url),
                title=alert.get("alert", "ZAP finding"),
                evidence=(alert.get("description") or "")[:500],
            ))
        return findings
