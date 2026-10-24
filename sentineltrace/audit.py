"""
SentinelTrace-EDR: Cryptographic Forensic Timeline & Non-Repudiation Audit Chain.
Implements an append-only SHA-256 Merkle-style evidence chain guaranteeing that
incident timelines cannot be retroactively falsified or altered.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any, List, Optional

from sentineltrace.types import ProcessEvent, ThreatAlert

GENESIS_FORENSIC_ROOT = hashlib.sha256(b"SENTINEL_TRACE_FORENSIC_ROOT_V1").hexdigest()


@dataclasses.dataclass(slots=True, frozen=True)
class ForensicTimelineNode:
    """Cryptographically chained node in the forensic incident timeline."""
    sequence: int
    event_id: str
    event_category: str
    item_digest: str
    prev_hash: str
    current_hash: str
    timestamp_ns: int


class ForensicAuditChain:
    """
    Immutable forensic timeline chain.
    """
    def __init__(self, genesis_hash: str = GENESIS_FORENSIC_ROOT) -> None:
        self.genesis_hash = genesis_hash
        self.current_hash = genesis_hash
        self.timeline: List[ForensicTimelineNode] = []

    def _compute_event_digest(self, event: ProcessEvent) -> str:
        h = hashlib.sha256()
        h.update(event.event_id.encode("utf-8"))
        h.update(event.event_type.encode("ascii"))
        h.update(event.pid.to_bytes(8, "big"))
        h.update(event.command_line.encode("utf-8", errors="replace"))
        h.update(event.timestamp_ns.to_bytes(8, "big"))
        return h.hexdigest()

    def _compute_alert_digest(self, alert: ThreatAlert) -> str:
        h = hashlib.sha256()
        h.update(alert.alert_id.encode("utf-8"))
        h.update(alert.rule_name.encode("utf-8"))
        h.update(alert.pid.to_bytes(8, "big"))
        h.update(alert.command_line.encode("utf-8", errors="replace"))
        h.update(alert.timestamp_ns.to_bytes(8, "big"))
        return h.hexdigest()

    def record_process_event(self, event: ProcessEvent) -> str:
        """Append a process telemetry event to the forensic chain."""
        digest = self._compute_event_digest(event)
        return self._append_node(event.event_id, "PROCESS_EVENT", digest, event.timestamp_ns)

    def record_threat_alert(self, alert: ThreatAlert) -> str:
        """Append a threat alert detection to the forensic chain."""
        digest = self._compute_alert_digest(alert)
        return self._append_node(alert.alert_id, "THREAT_ALERT", digest, alert.timestamp_ns)

    def _append_node(self, event_id: str, category: str, digest: str, timestamp_ns: int) -> str:
        seq = len(self.timeline) + 1
        h = hashlib.sha256()
        h.update(self.current_hash.encode("ascii"))
        h.update(seq.to_bytes(8, "big"))
        h.update(category.encode("ascii"))
        h.update(digest.encode("ascii"))
        h.update(timestamp_ns.to_bytes(8, "big"))
        new_hash = h.hexdigest()

        node = ForensicTimelineNode(
            sequence=seq,
            event_id=event_id,
            event_category=category,
            item_digest=digest,
            prev_hash=self.current_hash,
            current_hash=new_hash,
            timestamp_ns=timestamp_ns,
        )
        self.timeline.append(node)
        self.current_hash = new_hash
        return new_hash

    def verify_integrity(self) -> bool:
        """
        Verify that the entire historical forensic timeline chain is unbroken from genesis.
        Raises ValueError if tampering is detected.
        """
        expected_prev = self.genesis_hash

        for node in self.timeline:
            if node.prev_hash != expected_prev:
                raise ValueError(
                    f"Forensic Chain Broken at sequence {node.sequence}: "
                    f"expected prev_hash '{expected_prev}', got '{node.prev_hash}'."
                )

            h = hashlib.sha256()
            h.update(expected_prev.encode("ascii"))
            h.update(node.sequence.to_bytes(8, "big"))
            h.update(node.event_category.encode("ascii"))
            h.update(node.item_digest.encode("ascii"))
            h.update(node.timestamp_ns.to_bytes(8, "big"))
            expected_current = h.hexdigest()

            if node.current_hash != expected_current:
                raise ValueError(
                    f"Forensic Evidence Tampering Detected at sequence {node.sequence} (ID: {node.event_id}): "
                    f"Expected hash '{expected_current}', but node has '{node.current_hash}'."
                )

            expected_prev = expected_current

        return True
