"""
Unit & Integration Tests for SentinelTrace-EDR REST Incident & Telemetry Service.
"""

import pytest
from starlette.testclient import TestClient
from sentineltrace.server import app, engine


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "events_processed" in data
    assert data["audit_chain_verified"] is True


def test_dashboard_ui(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "SentinelTrace-EDR Security Operations Center" in response.text


def test_ingest_malicious_event_and_lineage(client):
    # Step 1: Ingest benign parent (winword.exe)
    parent_resp = client.post("/v1/telemetry/event", json={
        "event_type": "PROCESS_START",
        "pid": 2040,
        "ppid": 1000,
        "process_name": "winword.exe",
        "image_path": "C:\\Program Files\\Microsoft Office\\winword.exe",
        "command_line": "winword.exe invoice.docm",
        "parent_name": "explorer.exe",
        "user": "CORP\\victim",
    })
    assert parent_resp.status_code == 200
    assert parent_resp.json()["committed"] is True

    # Step 2: Ingest suspicious child (winword.exe spawning powershell.exe)
    child_resp = client.post("/v1/telemetry/event", json={
        "event_type": "PROCESS_START",
        "pid": 3100,
        "ppid": 2040,
        "process_name": "powershell.exe",
        "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -w hidden -enc JABzAD0ATgBl...",
        "parent_name": "winword.exe",
        "user": "CORP\\victim",
    })
    assert child_resp.status_code == 200
    child_data = child_resp.json()
    assert child_data["alerts_triggered"] >= 1
    # Check that alert triggered on Office macro execution
    rule_names = [a["rule_name"] for a in child_data["alerts"]]
    assert any("Office" in r or "Macro" in r or "PowerShell" in r for r in rule_names)

    # Step 3: Query ancestry tree for child PID 3100
    lineage_resp = client.get("/v1/lineage/3100")
    assert lineage_resp.status_code == 200
    lineage_data = lineage_resp.json()
    assert lineage_data["pid"] == 3100
    assert lineage_data["depth"] >= 2
    ancestor_procs = [p["process_name"] for p in lineage_data["ancestry"]]
    assert "powershell.exe" in ancestor_procs
    assert "winword.exe" in ancestor_procs


def test_stix_and_forensics_endpoints(client):
    # 1. Incident report
    report_resp = client.get("/v1/forensics/report")
    assert report_resp.status_code == 200
    report_data = report_resp.json()
    assert report_data["total_alerts"] >= 1
    assert "mitre_tactics" in report_data

    # 2. STIX 2.1 CTI bundle export
    stix_resp = client.get("/v1/stix/bundle")
    assert stix_resp.status_code == 200
    stix_data = stix_resp.json()
    assert stix_data["type"] == "bundle"
    assert len(stix_data["objects"]) >= 1
    # Verify standard STIX types
    stix_types = [obj["type"] for obj in stix_data["objects"]]
    assert "attack-pattern" in stix_types
    assert "indicator" in stix_types

    # 3. Cryptographic chain verify
    verify_resp = client.get("/v1/forensics/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json()["is_valid"] is True
