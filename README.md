# VulnX — Automated Vulnerability Assessment and Risk Prioritization System

A local-only academic MVP. It checks basic HTTP security configuration on loopback targets, stores findings in SQLite, ranks findings using a transparent illustrative risk model, and displays results in a React dashboard.

## Safety scope
- This starter only accepts loopback URLs (`localhost`, `127.0.0.1`, `::1`).
- It performs simple HTTP GET requests and security-header checks only.
- It is not a full vulnerability scanner and does not exploit vulnerabilities.
- Only scan systems you own or have explicit permission to assess.
- Risk scores are prioritization aids, not predictions of exploit probability.

## Requirements
- Python 3.10+
- Node.js 20.19+ or 22.12+ (use a supported LTS)
- npm

## 1. Start the backend (Windows PowerShell)
```powershell
cd VulnX\backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload
```
If PowerShell blocks activation, use `Set-ExecutionPolicy -Scope Process Bypass` in that terminal, then activate again. Or run `.venv\Scripts\python.exe -m pip install -r requirements.txt` and `.venv\Scripts\python.exe -m uvicorn app.main:app --reload`.

Backend: http://127.0.0.1:8000
API docs: http://127.0.0.1:8000/docs

## 2. Start the frontend (a second terminal)
```powershell
cd VulnX\frontend
npm install
npm run dev
```
Open the URL printed by Vite (usually http://localhost:5173).

## 3. Try a local target
For a quick safe demo, start a simple local test server in a third terminal:
```powershell
cd VulnX
py demo_target.py
```
Then enter `http://127.0.0.1:8080` in VulnX and click **Run assessment**. The result is only a basic header/configuration assessment.

To verify the exposure checks end to end, start the fixture with clearly synthetic fake sensitive files instead:
```powershell
py demo_target.py --expose-test-fixtures
```
This mode serves a fake `/.env`, `/.git/HEAD` and `/phpinfo.php` (all invented placeholder values, never real credentials) so the scanner reports real High/Medium exposure findings against a target you control. Run `py demo_target.py` without the flag as the fixed negative control: no exposure findings should appear.

## What this MVP checks
- Missing Content-Security-Policy (informational/low-priority configuration observation)
- Missing X-Content-Type-Options
- Missing Referrer-Policy
- Missing frame protection (X-Frame-Options or CSP `frame-ancestors`)
- HTTPS use (HTTP localhost is allowed for testing and will be reported as an observation, not as a vulnerability)
- Exposed sensitive files and debug information: one GET each on a fixed list of well-known paths (`/.env`, `/.git/HEAD`, `/phpinfo.php`, `/server-status`, `/actuator/env`, `/debug/vars`) of the loopback origin you entered.

Exposure-check findings are evidence-based:
- A finding requires HTTP 200 **and** a positive content marker for that file type.
- A 200 that returns the same body as the base page is treated as a catch-all route and skipped (false-positive control).
- Evidence is redacted: `.env` findings report key names only, never values; status/debug pages report only that the marker was observed.
- Severity reflects the exposure (`.env` and `.git` metadata = High, debug/status pages = Medium). Exploitation evidence remains zero because the tool never attempts exploitation.

Not every missing header is automatically a vulnerability; assess findings in context. The code intentionally avoids testing for SQL injection, XSS, authentication bypass, or other exploit-oriented conditions.

## Project structure
```text
VulnX/
  backend/app/main.py
  backend/app/scanner.py
  backend/app/risk.py
  backend/app/db.py
  backend/requirements.txt
  frontend/src/App.jsx
  frontend/src/main.jsx
  frontend/src/styles.css
  frontend/package.json
  frontend/index.html
```

## Important limitations / next steps
1. Add authentication before exposing the app beyond localhost.
2. Add a proper scan-job queue for long-running scans.
3. Integrate OWASP ZAP only for explicitly authorized lab targets, with scope restrictions.
4. Add CVSS/CVE metadata from trusted sources and document the scoring method.
5. Add PDF reporting and verified before/after remediation evaluation.
6. Add unit tests and validate results manually against known test cases.

## ConnectionError: check the three separate processes
1. Backend terminal: from `backend`, start `python -m uvicorn app.main:app --reload` (port 8000).
2. Frontend terminal: from `frontend`, run `npm ci` then `npm run dev` (port 5173).
3. Target terminal: from the folder containing this README, run `python demo_target.py` (port 8080).
4. Open the demo target URL in a browser first. Then assess `http://127.0.0.1:8080`.

The default demo is a fixed HTML page, not a directory server. All three processes must run on the same computer. A phone's `127.0.0.1` means the phone, not your laptop. Do not expose this unauthenticated prototype to the network.

A failed connection is not a vulnerability. Failed attempts are not saved in the current database schema, so zero assessments after a failed attempt is expected. If port 8080 is occupied, identify the existing service before stopping it, or edit the demo port and the target URL together. Do not disable your firewall or certificate checks to force a result.

## Repeatable local tests and production build
```powershell
# From backend, with the backend environment active:
pip install -r requirements-dev.txt
python -m unittest -v tests
# From frontend:
npm ci
npm run build
npm run preview
```
Preview uses port 4173, allowed by the backend CORS configuration. The dev server fails clearly if 5173 is busy rather than silently moving to a CORS-blocked port. For a non-default API address, set VITE_API_URL before starting/building the frontend. This does not authorize exposing the backend publicly.

## What results mean
The included HTTP demo intentionally omits checked headers. A local test gives five configuration observations: three Low and two Informational, all P4 - Low, top score 1.8. These are fixture results, not measurements of your friend's machine or a real production deployment. In default mode the exposure probes correctly find nothing, so High/Critical counters remain zero. With `--expose-test-fixtures`, the observed synthetic `.env` and `.git` exposures are reported as High. Never inflate a severity or invent a finding to populate those cards.

The formula is `0.40*severity_base + 0.20*exposure + 0.25*exploitation_evidence + 0.15*impact`. This starter sets exploitation evidence to zero. Weights are illustrative, not CVSS or a prediction of exploitation.

## Honest feature boundaries
Implemented: loopback URL validation, one HTTP GET without following redirects, selected missing-header checks, a bounded set of evidence-based exposed sensitive-file probes with redacted evidence, illustrative scoring, SQLite history and a dashboard.
Not implemented: network discovery, attack graphs, Nmap/OpenVAS/ZAP integration, CVE/CVSS lookup, exploit checks, authentication, PDF export, working navigation pages or job queues. Sidebar labels other than Overview are placeholders. Saved scans do not preserve HTTP status or the limitation string; this is a known history-metadata limitation. Header presence is not proof that the header value is safe. The exposure probes cover only their fixed path list and their specific content markers; a clean result does not prove no sensitive file is exposed.

## High/Critical simulated training mode
Use "Load simulated demo" for separate synthetic High/Critical examples. No target is scanned. The API, database, history and selected view retain `assessment_kind=simulated`; simulated records do not count as real assessments. Their titles, evidence and UI banner explicitly say simulated. The illustrative scores are 9.8 (Critical/P1) and 7.8 (High/P2). These invented values do not show that a real vulnerability exists.

Real High/Medium exposure detection is implemented only for the fixed probe list above, with the content-marker, catch-all and redaction controls described there. Detection of exploit-oriented High/Critical conditions (injection, auth bypass, RCE and similar) remains unimplemented by design.
