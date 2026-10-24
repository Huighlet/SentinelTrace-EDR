"""
SentinelTrace-EDR: Core Incident Engine & Forensic Coordinator.
Coordinates process lineage tracking, Sigma threat detection, cryptographic audit logging,
and STIX 2.1 forensic report generation.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from sentineltrace.audit import ForensicAuditChain
from sentineltrace.lineage import ProcessLineageGraph
from sentineltrace.rules import RuleEngine
from sentineltrace.types import MITRETactic, ProcessEvent, ProcessEventType, ThreatAlert, ThreatSeverity


class SentinelEngine:
    """
    High-Throughput Endpoint Detection and Forensic Response Engine.
    """
    def __init__(self) -> None:
        self.lineage = ProcessLineageGraph()
        self.rule_engine = RuleEngine()
        self.audit_chain = ForensicAuditChain()
        self._alerts: List[ThreatAlert] = []
        self._events_count: int = 0

    @property
    def alerts(self) -> List[ThreatAlert]:
        return list(self._alerts)

    @property
    def events_processed(self) -> int:
        return self._events_count

    def ingest_event(self, event: ProcessEvent) -> List[ThreatAlert]:
        """
        Ingest host telemetry event into lineage graph, evaluate detection rules,
        and cryptographically commit to forensic audit timeline.
        """
        self._events_count += 1
        alerts: List[ThreatAlert] = []

        # 1. Cryptographically commit raw event to timeline
        self.audit_chain.record_process_event(event)

        # 2. Process Start Lifecycle
        if event.event_type == ProcessEventType.PROCESS_START:
            self.lineage.register_start(event)

            # A. Behavioral Invariant Detectors (Macros, WebShells, Ransomware, LSASS)
            lineage_alerts = self.lineage.detect_anomalies(event)
            alerts.extend(lineage_alerts)

            # B. Sigma Rule Evaluation
            sigma_alerts = self.rule_engine.evaluate_event(event)
            alerts.extend(sigma_alerts)

            # C. Record all emitted alerts into forensic chain
            for alt in alerts:
                self.audit_chain.record_threat_alert(alt)
                self._alerts.append(alt)

        # 3. Process Termination Lifecycle
        elif event.event_type == ProcessEventType.PROCESS_TERMINATE:
            self.lineage.register_terminate(event.pid, event.timestamp_ns)

        return alerts

    def generate_incident_report(self) -> Dict[str, Any]:
        """Produce structured digital forensics and incident response report."""
        severity_counts = {s.name: 0 for s in ThreatSeverity}
        tactic_counts: Dict[str, int] = {}

        for alt in self._alerts:
            severity_counts[alt.severity.name] += 1
            tactic_counts[alt.tactic.name] = tactic_counts.get(alt.tactic.name, 0) + 1

        highest_severity = (
            max((alt.severity for alt in self._alerts), default=ThreatSeverity.INFO).name
        )

        return {
            "incident_id": f"INC_{uuid.uuid4().hex[:12].upper()}",
            "generated_at_ns": time.time_ns(),
            "events_processed": self._events_count,
            "total_alerts": len(self._alerts),
            "highest_severity": highest_severity,
            "severity_distribution": severity_counts,
            "mitre_tactics": tactic_counts,
            "forensic_chain_length": len(self.audit_chain.timeline),
            "forensic_chain_head": self.audit_chain.current_hash,
            "chain_verified": self.audit_chain.verify_integrity(),
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "rule": a.rule_name,
                    "severity": a.severity.name,
                    "tactic": a.tactic.name,
                    "technique": a.technique_id,
                    "pid": a.pid,
                    "ppid": a.ppid,
                    "process": a.process_name,
                    "cmd": a.command_line,
                    "evidence": a.evidence,
                }
                for a in self._alerts
            ],
        }

    def export_stix2(self) -> Dict[str, Any]:
        """Export forensic findings as a STIX 2.1 Cyber Threat Intelligence bundle."""
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects: List[Dict[str, Any]] = []

        for alt in self._alerts:
            indicator_id = f"indicator--{uuid.uuid4()}"
            attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"

            # 1. Attack Pattern Object
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pattern_id,
                "name": alt.rule_name,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": alt.technique_id,
                    }
                ],
            })

            # 2. Indicator Object
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "name": alt.rule_name,
                "description": alt.evidence,
                "pattern": f"[process:name = '{alt.process_name}' AND process:command_line = '{alt.command_line}']",
                "pattern_type": "stix",
                "valid_from": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

            # 3. Relationship
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": attack_pattern_id,
            })

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }
