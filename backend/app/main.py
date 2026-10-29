from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .db import init_db, list_scans, get_scan, save_scan
from .scanner import assess_target
from .demo import simulated_findings

app = FastAPI(title="VulnX API", version="0.1.0",
              description="Local-only academic MVP for basic security configuration assessment.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:4173", "http://127.0.0.1:4173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

@app.on_event("startup")
def startup():
    init_db()

class ScanRequest(BaseModel):
    target: str = Field(min_length=8, max_length=300)

@app.get("/api/health")
def health():
    return {"status": "ok", "app": "VulnX", "scope": "loopback-only"}

@app.post("/api/scans")
def create_scan(request: ScanRequest):
    try:
        result = assess_target(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    created_at = datetime.now(timezone.utc).isoformat()
    scan_id = save_scan(result["target"], created_at, result["findings"])
    return {
        "id": scan_id, "target": result["target"], "status": "Completed", "assessment_kind": "actual",
        "created_at": created_at, "http_status": result["http_status"],
        "total_findings": len(result["findings"]), "findings": result["findings"],
        "limitations": result["limitations"]
    }

@app.get("/api/scans")
def scans():
    return list_scans()

@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: int):
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.post("/api/demos")
def create_demo():
    findings = simulated_findings()
    created_at = datetime.now(timezone.utc).isoformat()
    target = "SIMULATED TRAINING DATA - no target scanned"
    scan_id = save_scan(target, created_at, findings, assessment_kind="simulated")
    return get_scan(scan_id)
