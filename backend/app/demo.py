"""Synthetic examples only. This module makes no network requests."""
from .risk import score_finding

def simulated_findings():
    examples = [("Critical", "Synthetic critical-risk scenario", 10, 10, 10),
                ("High", "Synthetic high-risk scenario", 8, 8, 8)]
    return [{"title": "SIMULATED: " + title, "severity": severity,
             "description": "Training example only. No vulnerability was detected and no target was scanned.",
             "evidence": f"SYNTHETIC inputs: severity={severity}, exposure={exposure}, exploitation_evidence={evidence}, impact={impact}. These values are invented for demonstration, not observed.",
             "remediation": "No real remediation is justified by this example. Validate evidence on an authorized target before acting.",
             **score_finding(severity, exposure, evidence, impact)}
            for severity, title, exposure, evidence, impact in examples]
