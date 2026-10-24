"""
Enterprise and Client SDK tests for SentinelTrace-EDR.
Validates Pillar 1 (Enterprise Middleware & Metrics), Pillar 2 (Host Quarantine & DFIR Snapshot), and Pillar 3 (Client SDK).
"""

import pytest
from starlette.testclient import TestClient

from sentineltrace import server
from sentineltrace.client import SentinelTraceClient


@pytest.fixture
def test_client() -> TestClient:
    return TestClient(server.app)


def test_prometheus_metrics_endpoint(test_client: TestClient):
    resp = test_client.get("/metrics")
    assert resp.status_code == 200
    text = resp.text
    assert "sentineltrace_events_processed_total" in text
    assert "sentineltrace_threat_alerts_total" in text
    assert "sentineltrace_audit_chain_length" in text


def test_host_quarantine_endpoint(test_client: TestClient):
    payload = {"pid": 9999, "reason": "Active Cobalt Strike Beacon detected"}
    resp = test_client.post("/v1/host/quarantine", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HOST_CONTAINED"
    assert data["network_isolated"] is True
    assert data["pid"] == 9999


def test_forensics_snapshot_endpoint(test_client: TestClient):
    resp = test_client.get("/v1/forensics/snapshot")
    assert resp.status_code == 200
    data = resp.json()
    assert "incident_report" in data
    assert "stix_bundle" in data
    assert "audit_chain_verified" in data


def test_sentineltrace_python_client_sdk(test_client: TestClient):
    client = SentinelTraceClient(http_client=test_client)

    # 1. Ingest Event
    evt = client.ingest_event(
        pid=5500,
        ppid=1000,
        process_name="powershell.exe",
        command_line="powershell.exe -enc SQBFAFgA",
        image_path="C:\\Windows\\powershell.exe",
        parent_name="winword.exe",
    )
    assert evt["committed"] is True
    assert evt["alerts_triggered"] >= 1

    # 2. Lineage
    lineage = client.get_process_lineage(5500)
    assert lineage["pid"] == 5500

    # 3. Quarantine via SDK
    quar = client.quarantine_host(pid=5500, reason="Macro execution")
    assert quar["status"] == "HOST_CONTAINED"

    # 4. Verify audit chain
    audit = client.verify_audit_chain()
    assert audit["is_valid"] is True
    client.close()
