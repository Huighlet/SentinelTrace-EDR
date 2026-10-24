"""
SentinelTrace Client SDK: Idiomatic high-performance client for the SentinelTrace-EDR Telemetry & SOC Server.
Supports process lifecycle event streaming, parent-child lineage traversal, Sigma alert querying, host containment, and STIX 2.1 export.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore


class SentinelTraceClient:
    """
    Client for interacting with a live SentinelTrace-EDR endpoint agent server.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8090",
        api_key: Optional[str] = None,
        timeout_seconds: float = 10.0,
        http_client: Optional[Any] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        if http_client is not None:
            self._client = http_client
        elif httpx is not None:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout_seconds,
            )
        else:
            self._client = None

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> SentinelTraceClient:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def ingest_event(
        self,
        pid: int,
        ppid: int,
        process_name: str,
        command_line: str,
        image_path: str,
        parent_name: str,
        event_type: str = "PROCESS_START",
        user: str = "SYSTEM",
        sha256: str = "",
        event_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ingest host process execution telemetry event."""
        payload = {
            "event_type": event_type,
            "pid": pid,
            "ppid": ppid,
            "process_name": process_name,
            "command_line": command_line,
            "image_path": image_path,
            "parent_name": parent_name,
            "user": user,
            "sha256": sha256,
            "event_id": event_id or f"evt_{uuid.uuid4().hex[:12]}",
        }
        resp = self._client.post("/v1/telemetry/event", json=payload)
        resp.raise_for_status()
        return resp.json()

    def get_process_lineage(self, pid: int) -> Dict[str, Any]:
        """Query complete ancestor tree from node to root for process forensics."""
        resp = self._client.get(f"/v1/lineage/{pid}")
        resp.raise_for_status()
        return resp.json()

    def get_alerts(self) -> Dict[str, Any]:
        """Retrieve all detected threat alerts."""
        resp = self._client.get("/v1/alerts")
        resp.raise_for_status()
        return resp.json()

    def get_incident_report(self) -> Dict[str, Any]:
        """Generate structured DFIR incident report."""
        resp = self._client.get("/v1/forensics/report")
        resp.raise_for_status()
        return resp.json()

    def export_stix_bundle(self) -> Dict[str, Any]:
        """Export detection findings as a STIX 2.1 Cyber Threat Intelligence bundle."""
        resp = self._client.get("/v1/stix/bundle")
        resp.raise_for_status()
        return resp.json()

    def verify_audit_chain(self) -> Dict[str, Any]:
        """Cryptographically verify integrity of the SHA-256 Merkle audit timeline."""
        resp = self._client.get("/v1/forensics/verify")
        resp.raise_for_status()
        return resp.json()

    def quarantine_host(self, pid: int, reason: str = "Active threat detected") -> Dict[str, Any]:
        """Trigger automated host isolation and process suspension."""
        payload = {"pid": pid, "reason": reason}
        resp = self._client.post("/v1/host/quarantine", json=payload)
        resp.raise_for_status()
        return resp.json()

    def get_metrics(self) -> str:
        """Fetch Prometheus metrics."""
        resp = self._client.get("/metrics")
        resp.raise_for_status()
        return resp.text
