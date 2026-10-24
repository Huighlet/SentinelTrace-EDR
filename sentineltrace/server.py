"""
SentinelTrace-EDR: Production Host Telemetry & SOC Incident Response Server.
Provides real-time process telemetry ingest, lineage graph analysis, Sigma detection,
cryptographic SHA-256 audit chain verification, STIX 2.1 CTI export, and interactive developer UI.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from sentineltrace.engine import SentinelEngine
from sentineltrace.types import MITRETactic, ProcessEvent, ProcessEventType, ThreatSeverity


# ---------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------

class IngestEventRequest(BaseModel):
    event_type: str = Field("PROCESS_START", description="Event classification: 'PROCESS_START' or 'PROCESS_TERMINATE'")
    pid: int = Field(..., description="Process Identifier (PID)")
    ppid: int = Field(..., description="Parent Process Identifier (PPID)")
    process_name: str = Field(..., description="Binary executable name (e.g. 'powershell.exe')")
    command_line: str = Field(..., description="Command-line arguments string")
    image_path: str = Field(..., description="Full filesystem executable path")
    parent_name: str = Field(..., description="Parent process executable name (e.g. 'excel.exe')")
    user: str = Field("SYSTEM", description="Executing user account or security context")
    sha256: Optional[str] = Field("", description="SHA-256 binary hash digest")
    event_id: Optional[str] = Field(None, description="Event ID. Generated if omitted.")


# ---------------------------------------------------------
# Engine Initialization
# ---------------------------------------------------------

app = FastAPI(
    title="SentinelTrace-EDR Host Telemetry & Incident Engine",
    description="Endpoint Detection & Response (EDR) microservice with process lineage DAG tracking, LOLBin behavioral detection, cryptographic Merkle audit logging, and STIX 2.1 CTI bundles.",
    version="1.0.0",
)

engine = SentinelEngine()


# ---------------------------------------------------------
# Developer UI Dashboard
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def edr_dashboard():
    """Interactive SOC Analyst & EDR Telemetry Dashboard."""
    report = engine.generate_incident_report()
    recent_alerts = engine.alerts[-5:]

    alerts_rows = "".join(
        f"<tr><td><code>{a.alert_id}</code></td><td><strong>{a.severity.name}</strong></td><td>{a.rule_name}</td><td>{a.tactic.name} ({a.technique_id})</td><td><code>{a.process_name}</code> (PID: {a.pid})</td></tr>"
        for a in recent_alerts
    )
    if not alerts_rows:
        alerts_rows = "<tr><td colspan='5' style='text-align:center;color:#9ca3af;'>Zero incidents detected. Host is clean. Submit telemetry event to simulate attack.</td></tr>"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SentinelTrace-EDR SOC Analyst Console</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0b0f19; color: #f3f4f6; margin: 0; padding: 32px; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
            h1 {{ color: #e11d48; margin-top: 0; font-size: 24px; font-weight: 600; }}
            p {{ color: #9ca3af; font-size: 14px; line-height: 1.5; }}
            .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
            .card {{ background: #1f2937; padding: 14px; border-radius: 6px; border-left: 3px solid #e11d48; }}
            .card-label {{ font-size: 11px; text-transform: uppercase; color: #9ca3af; }}
            .card-val {{ font-size: 22px; font-weight: 700; color: #f9fafb; margin-top: 4px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
            th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #374151; }}
            th {{ background: #1f2937; color: #9ca3af; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
            .btn {{ display: inline-block; padding: 9px 16px; border-radius: 6px; background: #e11d48; color: #ffffff; text-decoration: none; font-size: 13px; font-weight: 600; margin-right: 8px; }}
            .btn:hover {{ background: #be123c; }}
            code {{ background: #1f2937; padding: 2px 6px; border-radius: 4px; color: #fda4af; }}
            pre {{ background: #030712; padding: 14px; border-radius: 6px; color: #fda4af; font-size: 12px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SentinelTrace-EDR Security Operations Center</h1>
            <p>Behavioral Host Endpoint Detection & Response microservice with parent-child process lineage DAG tracking, Sigma rule engine, and cryptographic SHA-256 audit logs.</p>

            <div class="metrics">
                <div class="card">
                    <div class="card-label">Events Processed</div>
                    <div class="card-val">{report['events_processed']:,}</div>
                </div>
                <div class="card">
                    <div class="card-label">Active Threats</div>
                    <div class="card-val">{report['total_alerts']:,}</div>
                </div>
                <div class="card">
                    <div class="card-label">Chain Verified</div>
                    <div class="card-val" style="color: {'#34d399' if report['chain_verified'] else '#ef4444'}">{'VALID' if report['chain_verified'] else 'CORRUPT'}</div>
                </div>
                <div class="card">
                    <div class="card-label">Highest Severity</div>
                    <div class="card-val">{report['highest_severity']}</div>
                </div>
            </div>

            <p>
                <a href="/docs" class="btn">Explore OpenAPI / Swagger &rarr;</a>
                <a href="/v1/stix/bundle" class="btn" style="background: #374151;">Export STIX 2.1 CTI Bundle</a>
                <a href="/v1/forensics/report" class="btn" style="background: #374151;">DFIR Incident Report</a>
            </p>

            <h3>Recent Threat Detections</h3>
            <table>
                <thead>
                    <tr><th>Alert ID</th><th>Severity</th><th>Rule Name</th><th>MITRE Tactic</th><th>Process (PID)</th></tr>
                </thead>
                <tbody>
                    {alerts_rows}
                </tbody>
            </table>

            <h3>Simulate Malicious Office Macro Execution (Excel Spawning PowerShell)</h3>
            <pre>curl -X POST http://localhost:8090/v1/telemetry/event \\
  -H "Content-Type: application/json" \\
  -d '{{
    "event_type": "PROCESS_START",
    "pid": 5892,
    "ppid": 1420,
    "process_name": "powershell.exe",
    "parent_name": "excel.exe",
    "command_line": "powershell.exe -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...",
    "image_path": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "user": "DOMAIN\\\\victim_finance"
  }}'</pre>
        </div>
    </body>
    </html>
    """


# ---------------------------------------------------------
# Health & Telemetry Endpoints
# ---------------------------------------------------------

@app.get("/health")
def health():
    """Liveness probe & incident metrics."""
    return {
        "status": "HEALTHY",
        "timestamp_ns": time.time_ns(),
        "events_processed": engine.events_processed,
        "total_alerts": len(engine.alerts),
        "audit_chain_verified": engine.audit_chain.verify_integrity(),
    }


@app.post("/v1/telemetry/event")
def ingest_event(req: IngestEventRequest):
    """
    Ingest host telemetry event into lineage graph, evaluate behavioral detectors & Sigma rules,
    and cryptographically commit to the forensic audit chain.
    """
    event_id = req.event_id or f"evt_{uuid.uuid4().hex[:12]}"
    try:
        ev_type = ProcessEventType(req.event_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid event_type: '{req.event_type}'")

    event = ProcessEvent(
        event_id=event_id,
        event_type=ev_type,
        pid=req.pid,
        ppid=req.ppid,
        process_name=req.process_name,
        image_path=req.image_path,
        command_line=req.command_line,
        parent_name=req.parent_name,
        user=req.user,
        sha256=req.sha256 or "",
    )

    alerts = engine.ingest_event(event)

    return {
        "event_id": event.event_id,
        "committed": True,
        "alerts_triggered": len(alerts),
        "alerts": [
            {
                "alert_id": a.alert_id,
                "rule_name": a.rule_name,
                "severity": a.severity.name,
                "tactic": a.tactic.name,
                "technique_id": a.technique_id,
                "evidence": a.evidence,
            }
            for a in alerts
        ],
        "audit_chain_head": engine.audit_chain.current_hash,
    }


@app.get("/v1/lineage/{pid}")
def get_process_lineage(pid: int):
    """Retrieve full ancestor tree for a process from child node up to root parent."""
    ancestry = engine.lineage.get_ancestry(pid)
    if not ancestry:
        raise HTTPException(status_code=404, detail=f"PID {pid} not found in lineage graph.")

    return {
        "pid": pid,
        "depth": len(ancestry),
        "ancestry": [
            {
                "pid": node.pid,
                "ppid": node.ppid,
                "process_name": node.process_name,
                "command_line": node.command_line,
                "user": node.user,
                "is_active": node.is_active,
                "start_time_ns": node.start_time_ns,
            }
            for node in ancestry
        ],
    }


@app.get("/v1/alerts")
def get_all_alerts():
    """Retrieve all detected threat alerts."""
    return {
        "count": len(engine.alerts),
        "alerts": [
            {
                "alert_id": a.alert_id,
                "rule_name": a.rule_name,
                "severity": a.severity.name,
                "tactic": a.tactic.name,
                "technique_id": a.technique_id,
                "pid": a.pid,
                "ppid": a.ppid,
                "process_name": a.process_name,
                "command_line": a.command_line,
                "evidence": a.evidence,
                "timestamp_ns": a.timestamp_ns,
            }
            for a in engine.alerts
        ],
    }


@app.get("/v1/forensics/report")
def get_incident_report():
    """Generate structured Digital Forensics and Incident Response (DFIR) report."""
    return engine.generate_incident_report()


@app.get("/v1/stix/bundle")
def export_stix_bundle():
    """Export threat detections formatted as STIX 2.1 Cyber Threat Intelligence bundle."""
    return engine.export_stix2()


@app.get("/v1/forensics/verify")
def verify_audit_chain():
    """Cryptographically verify integrity of the SHA-256 Merkle audit timeline."""
    is_valid = engine.audit_chain.verify_integrity()
    return {
        "is_valid": is_valid,
        "chain_length": len(engine.audit_chain.timeline),
        "chain_head": engine.audit_chain.current_hash,
    }


def serve(host: str = "0.0.0.0", port: int = 8090):
    """Launch SentinelTrace REST Incident service."""
    import uvicorn
    uvicorn.run("sentineltrace.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    serve()
