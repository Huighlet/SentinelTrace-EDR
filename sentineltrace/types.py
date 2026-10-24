"""
SentinelTrace-EDR: Core Types, Telemetry Events, and MITRE ATT&CK Mappings.
"""

from __future__ import annotations

import dataclasses
import enum
import time
from typing import Any, Dict, Optional


class ProcessEventType(enum.StrEnum):
    """Host telemetry event classification."""
    PROCESS_START = "PROCESS_START"
    PROCESS_TERMINATE = "PROCESS_TERMINATE"
    NETWORK_CONNECT = "NETWORK_CONNECT"
    FILE_MODIFICATION = "FILE_MODIFICATION"


class ThreatSeverity(enum.IntEnum):
    """Threat severity ranking for triage."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class MITRETactic(enum.StrEnum):
    """MITRE ATT&CK Enterprise Matrix Tactics."""
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    IMPACT = "TA0040"


@dataclasses.dataclass(slots=True, frozen=True)
class ProcessEvent:
    """Atomic telemetry event captured from host kernel/event pipeline."""
    event_id: str
    event_type: ProcessEventType
    pid: int
    ppid: int
    process_name: str
    image_path: str
    command_line: str
    parent_name: str
    user: str
    sha256: str = ""
    timestamp_ns: int = dataclasses.field(default_factory=time.time_ns)


@dataclasses.dataclass(slots=True, frozen=True)
class ThreatAlert:
    """Security alert emitted upon behavioral rule or lineage invariant violation."""
    alert_id: str
    rule_name: str
    severity: ThreatSeverity
    tactic: MITRETactic
    technique_id: str
    pid: int
    ppid: int
    process_name: str
    command_line: str
    parent_name: str
    evidence: str
    timestamp_ns: int = dataclasses.field(default_factory=time.time_ns)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
