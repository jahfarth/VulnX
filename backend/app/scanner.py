from urllib.parse import urlparse
import ipaddress
import json
import re
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
        base_body = response.content[:MAX_BODY_BYTES]
        exposure_findings = check_exposed_paths(session, target, base_body)
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

    findings.extend(exposure_findings)

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
        "limitations": "Local-only HTTP configuration checks plus a fixed set of well-known exposed sensitive-file probes; not a full vulnerability scan."
    }


MAX_BODY_BYTES = 16384

def _fetch_limited(session, url):
    """Single GET returning (status, body capped at MAX_BODY_BYTES)."""
    with session.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=False, stream=True,
                     headers={"User-Agent": "VulnX-Academic-Assessment/1.0"}) as response:
        chunks, read = [], 0
        for chunk in response.iter_content(4096):
            chunks.append(chunk)
            read += len(chunk)
            if read >= MAX_BODY_BYTES:
                break
        return response.status_code, b"".join(chunks)[:MAX_BODY_BYTES]

_ENV_KEY = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
_GIT_HEAD = re.compile(r"^(ref:\s+refs/\S+|[0-9a-f]{40})\s*$")

def _env_match(text):
    """Return key-name list if the body looks like a KEY=VALUE environment file."""
    if "<" in text[:200]:  # HTML error page, not an env file
        return None
    keys = [m.group(1) for line in text.splitlines() if (m := _ENV_KEY.match(line))]
    return keys if len(keys) >= 2 else None

def _json_keys_match(text, required_key):
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if isinstance(data, dict) and required_key in data:
        return sorted(str(k) for k in data.keys())[:10]
    return None

# Bounded, non-invasive exposure checks: one GET each on well-known paths of the
# loopback target the user entered. A finding requires HTTP 200 plus a positive
# content marker, and is skipped when the body equals the base page (catch-all route).
EXPOSURE_PROBES = [
    {"path": "/.env", "kind": "env", "severity": "High", "exposure": 8, "impact": 8,
     "title": "Exposed environment configuration file (.env)",
     "description": "A .env-style file containing configuration entries is publicly reachable over HTTP. Such files typically hold credentials and secrets.",
     "remediation": "Remove the file from the web root, block dotfile access in the web server configuration, and rotate every credential the file contained."},
    {"path": "/.git/HEAD", "kind": "git_head", "severity": "High", "exposure": 8, "impact": 6,
     "title": "Exposed Git repository metadata",
     "description": "The repository's .git/HEAD file is publicly reachable, indicating the source-control metadata directory is exposed.",
     "remediation": "Block access to .git in the web server configuration and remove the directory from deployed web roots."},
    {"path": "/phpinfo.php", "kind": "phpinfo", "severity": "Medium", "exposure": 6, "impact": 5,
     "title": "Exposed PHP debug information page (phpinfo)",
     "description": "A phpinfo() page is publicly reachable, disclosing detailed runtime and configuration information.",
     "remediation": "Remove phpinfo() pages from deployed environments; restrict diagnostics to authenticated administrators."},
    {"path": "/server-status", "kind": "server_status", "severity": "Medium", "exposure": 6, "impact": 4,
     "title": "Exposed server status page",
     "description": "A web server status page is publicly reachable, disclosing operational details.",
     "remediation": "Restrict the status page to localhost or authenticated administrators in the server configuration."},
    {"path": "/actuator/env", "kind": "actuator_env", "severity": "Medium", "exposure": 6, "impact": 6,
     "title": "Exposed Spring Actuator environment endpoint",
     "description": "The /actuator/env endpoint is publicly reachable and returns environment property metadata.",
     "remediation": "Disable or secure management endpoints (management.endpoints.web exposure settings) and require authentication."},
    {"path": "/debug/vars", "kind": "debug_vars", "severity": "Medium", "exposure": 6, "impact": 4,
     "title": "Exposed Go expvar debug endpoint",
     "description": "The /debug/vars endpoint is publicly reachable, disclosing runtime diagnostics.",
     "remediation": "Bind expvar/pprof handlers to localhost or protect them with authentication."},
]

def _probe_evidence(kind, text, byte_count, truncated):
    """Return evidence text (sensitive values redacted) when the marker matches, else None."""
    note = f"HTTP 200, {byte_count} bytes read{' (truncated)' if truncated else ''}."
    if kind == "env":
        keys = _env_match(text)
        if keys is None:
            return None
        shown = ", ".join(keys[:10]) + (" ..." if len(keys) > 10 else "")
        return f"{note} Body matches KEY=VALUE environment-file format with {len(keys)} entries. Key names only, values redacted: {shown}"
    if kind == "git_head":
        first = text.strip().splitlines()[0].strip() if text.strip() else ""
        if _GIT_HEAD.match(first):
            return f"{note} .git/HEAD content observed: {first}"
        return None
    if kind == "phpinfo":
        if "phpinfo()" in text or ("PHP Version" in text and "php" in text.lower()):
            return f"{note} phpinfo marker observed in the response body. Body content not reproduced."
        return None
    if kind == "server_status":
        if "Apache Server Status" in text or "Server uptime" in text:
            return f"{note} Apache server-status marker observed. Body content not reproduced."
        return None
    if kind == "actuator_env":
        keys = _json_keys_match(text, "propertySources")
        if keys is not None:
            return f"{note} JSON response contains Spring 'propertySources' structure. Top-level keys only, values redacted: {', '.join(keys)}"
        return None
    if kind == "debug_vars":
        keys = _json_keys_match(text, "memstats") or _json_keys_match(text, "cmdline")
        if keys is not None:
            return f"{note} JSON response contains expvar diagnostics. Top-level keys only, values redacted: {', '.join(keys)}"
        return None
    return None

def check_exposed_paths(session, target, base_body):
    """Probe a fixed list of well-known sensitive paths on the entered loopback origin."""
    parsed = urlparse(target)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    findings = []
    for probe in EXPOSURE_PROBES:
        url = origin + probe["path"]
        try:
            status, body = _fetch_limited(session, url)
        except requests.RequestException:
            continue  # a failed probe is not evidence of anything
        if status != 200:
            continue
        if body == base_body:
            continue  # catch-all route returned the base page: not an exposed file
        text = body.decode("utf-8", errors="replace")
        evidence = _probe_evidence(probe["kind"], text, len(body), len(body) >= MAX_BODY_BYTES)
        if evidence is None:
            continue
        findings.append(_finding(probe["title"], probe["severity"], probe["description"],
                                 f"GET {probe['path']} -> {evidence}",
                                 probe["remediation"],
                                 exposure=probe["exposure"], impact=probe["impact"]))
    return findings
