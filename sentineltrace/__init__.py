"""
SentinelTrace-EDR: Lightweight Host-Level Threat Detection & Cryptographic Forensic Timeline Engine.
"""

from sentineltrace.audit import ForensicAuditChain, ForensicTimelineNode, GENESIS_FORENSIC_ROOT
from sentineltrace.engine import SentinelEngine
from sentineltrace.lineage import ProcessLineageGraph, ProcessNode
from sentineltrace.rules import RuleEngine, SigmaRule
from sentineltrace.types import (
    MITRETactic,
    ProcessEvent,
    ProcessEventType,
    ThreatAlert,
    ThreatSeverity,
)

__version__ = "1.0.0"

__all__ = [
    "SentinelEngine",
    "ProcessLineageGraph",
    "ProcessNode",
    "RuleEngine",
    "SigmaRule",
    "ForensicAuditChain",
    "ForensicTimelineNode",
    "GENESIS_FORENSIC_ROOT",
    "ProcessEvent",
    "ProcessEventType",
    "ThreatAlert",
    "ThreatSeverity",
    "MITRETactic",
]
