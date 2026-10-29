"""Transparent, illustrative prioritization model for the VulnX academic MVP."""

SEVERITY_BASE = {
    "Critical": 9.5,
    "High": 7.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Informational": 1.0,
}

def score_finding(severity: str, exposure: float = 5.0, exploitation_evidence: float = 0.0,
                  impact: float = 5.0) -> dict:
    """
    Inputs are 0-10 values. Weights are an illustrative project choice, not an industry standard.
    This MVP does not infer active exploitation; callers must provide verified evidence.
    """
    base = SEVERITY_BASE.get(severity, 1.0)
    exposure = max(0.0, min(10.0, float(exposure)))
    exploitation_evidence = max(0.0, min(10.0, float(exploitation_evidence)))
    impact = max(0.0, min(10.0, float(impact)))
    score = 0.40 * base + 0.20 * exposure + 0.25 * exploitation_evidence + 0.15 * impact
    score = round(max(0.0, min(10.0, score)), 1)
    if score >= 9.0:
        priority = "P1 - Urgent"
    elif score >= 7.0:
        priority = "P2 - High"
    elif score >= 4.5:
        priority = "P3 - Normal"
    else:
        priority = "P4 - Low"
    return {"risk_score": score, "priority": priority}
