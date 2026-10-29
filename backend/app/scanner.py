from urllib.parse import urlparse
import ipaddress
import requests
from .risk import score_finding

TIMEOUT_SECONDS = 5

def validate_loopback_target(url: str) -> str:
    """Accept only http(s) URLs whose host is localhost or a loopback IP."""
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("A valid hostname is required")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not allowed")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Port must be a number between 0 and 65535") from exc
    host = parsed.hostname.lower()
    if host == "localhost":
        return url
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Do not resolve arbitrary hostnames: this MVP is intentionally local-only.
        raise ValueError("For this MVP, use localhost, 127.0.0.1, or ::1 only")
    if not ip.is_loopback:
        raise ValueError("Only loopback targets are allowed in this MVP")
    return url

def _finding(title, severity, description, evidence, remediation, exposure=2, impact=3):
    score = score_finding(severity, exposure=exposure, exploitation_evidence=0, impact=impact)
    return {
        "title": title, "severity": severity, "description": description,
        "evidence": evidence, "remediation": remediation,
        "risk_score": score["risk_score"], "priority": score["priority"]
    }

def assess_target(url: str):
    target = validate_loopback_target(url)
    try:
        # Do not send local assessments through environment-configured proxies.
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(target, timeout=TIMEOUT_SECONDS, allow_redirects=False,
                                   headers={"User-Agent": "VulnX-Academic-Assessment/1.0"})
    except requests.exceptions.SSLError as exc:
        raise ValueError("TLS verification failed. Use a valid local certificate, or the HTTP demo target; certificate checks were not disabled.") from exc
    except requests.exceptions.Timeout as exc:
        raise ValueError(f"The local target did not respond within {TIMEOUT_SECONDS} seconds. Check that the target server is running.") from exc
    except requests.exceptions.ConnectionError as exc:
        raise ValueError("Cannot connect to the local target. Start its web server in a separate terminal and check the URL and port. For the included demo, run: python demo_target.py (port 8080).") from exc
    except requests.RequestException as exc:
        raise ValueError(f"Could not reach the local target: {exc.__class__.__name__}") from exc

    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = []

    checks = [
        ("content-security-policy", "Missing Content-Security-Policy header", "Low",
         "A Content Security Policy can reduce the impact of some content-injection attacks.",
         "Define a policy appropriate for the application, test it in report-only mode, then enforce it carefully."),
        ("x-content-type-options", "Missing X-Content-Type-Options header", "Low",
         "The response does not explicitly disable MIME-type sniffing.",
         "Set X-Content-Type-Options: nosniff where appropriate."),
        ("referrer-policy", "Missing Referrer-Policy header", "Informational",
         "The response does not specify an explicit referrer policy.",
         "Choose a Referrer-Policy that balances privacy and application requirements."),
    ]
    for header, title, severity, description, remediation in checks:
        if header not in headers:
            findings.append(_finding(title, severity, description,
                f"Response did not include the {header} header.",
                remediation, exposure=2, impact=2))

    csp = headers.get("content-security-policy", "")
    xfo = headers.get("x-frame-options", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        findings.append(_finding(
            "No explicit anti-framing policy detected", "Low",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
            "Response did not include X-Frame-Options or CSP frame-ancestors.",
            "Configure an appropriate frame-ancestors CSP directive or X-Frame-Options, considering legitimate embedding needs.",
            exposure=2, impact=3
        ))

    if url.lower().startswith("http://"):
        findings.append(_finding(
            "Target uses HTTP rather than HTTPS", "Informational",
            "The supplied local target uses unencrypted HTTP. This is expected for many local demos and is not by itself proof of a vulnerability.",
            "Assessment URL uses the http scheme.",
            "For deployed applications, use HTTPS with a valid certificate and redirect HTTP to HTTPS where appropriate.",
            exposure=1, impact=2
        ))

    if not findings:
        findings.append(_finding(
            "No issues found by the configured basic checks", "Informational",
            "The limited VulnX header/configuration checks did not identify missing checked headers.",
            "All configured basic response-header checks passed.",
            "This does not prove the application is secure. Use a broader authorized assessment and manual verification.",
            exposure=1, impact=1
        ))

    return {
        "target": target,
        "http_status": response.status_code,
        "server_header_present": "server" in headers,
        "findings": findings,
        "limitations": "Basic local-only HTTP configuration checks; not a full vulnerability scan."
    }
