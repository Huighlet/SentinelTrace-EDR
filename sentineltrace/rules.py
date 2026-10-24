"""
SentinelTrace-EDR: Sigma-Style Threat Hunting Rule Engine.
Evaluates process telemetry against declarative detection rules mapped to MITRE ATT&CK techniques.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Callable, Dict, List, Optional

from sentineltrace.types import MITRETactic, ProcessEvent, ThreatAlert, ThreatSeverity


@dataclasses.dataclass(slots=True, frozen=True)
class SigmaRule:
    """Detection rule specification."""
    rule_id: str
    title: str
    severity: ThreatSeverity
    tactic: MITRETactic
    technique_id: str
    process_regex: Optional[re.Pattern] = None
    command_regex: Optional[re.Pattern] = None
    parent_regex: Optional[re.Pattern] = None

    def evaluate(self, event: ProcessEvent) -> bool:
        """Evaluate if process event satisfies rule criteria."""
        if self.process_regex and not self.process_regex.search(event.process_name):
            return False

        if self.command_regex and not self.command_regex.search(event.command_line):
            return False

        if self.parent_regex and not self.parent_regex.search(event.parent_name):
            return False

        return True


class RuleEngine:
    """
    Evaluates process creation events against active rule catalog.
    """
    def __init__(self) -> None:
        self.rules: List[SigmaRule] = []
        self._load_standard_rules()

    def add_rule(self, rule: SigmaRule) -> None:
        self.rules.append(rule)

    def _load_standard_rules(self) -> None:
        """Load curated behavioral Sigma detection rules."""
        self.rules.extend([
            # 1. Certutil Ingress Tool Transfer
            SigmaRule(
                rule_id="SIG_001",
                title="Certutil Suspicious Ingress File Download",
                severity=ThreatSeverity.HIGH,
                tactic=MITRETactic.EXECUTION,
                technique_id="T1105",
                process_regex=re.compile(r"^certutil(\.exe)?$", re.IGNORECASE),
                command_regex=re.compile(r"-(urlcache|split|f)\s+http", re.IGNORECASE),
            ),
            # 2. PowerShell Encoded Script Execution
            SigmaRule(
                rule_id="SIG_002",
                title="Obfuscated PowerShell Encoded Command Execution",
                severity=ThreatSeverity.HIGH,
                tactic=MITRETactic.DEFENSE_EVASION,
                technique_id="T1059.001",
                process_regex=re.compile(r"^(powershell|pwsh)(\.exe)?$", re.IGNORECASE),
                command_regex=re.compile(r"-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,}", re.IGNORECASE),
            ),
            # 3. Unauthorized Local Account Creation
            SigmaRule(
                rule_id="SIG_003",
                title="Suspicious Local Administrator Account Creation",
                severity=ThreatSeverity.HIGH,
                tactic=MITRETactic.PERSISTENCE,
                technique_id="T1136.001",
                process_regex=re.compile(r"^net(\.exe)?$", re.IGNORECASE),
                command_regex=re.compile(r"(user\s+.*\/add|localgroup\s+administrators\s+.*\/add)", re.IGNORECASE),
            ),
            # 4. Registry Run Key Persistence
            SigmaRule(
                rule_id="SIG_004",
                title="Registry Run Key Persistence Modification",
                severity=ThreatSeverity.MEDIUM,
                tactic=MITRETactic.PERSISTENCE,
                technique_id="T1547.001",
                process_regex=re.compile(r"^reg(\.exe)?$", re.IGNORECASE),
                command_regex=re.compile(r"add\s+.*\\CurrentVersion\\Run", re.IGNORECASE),
            ),
            # 5. Suspicious User Reconnaissance
            SigmaRule(
                rule_id="SIG_005",
                title="Privilege and User Discovery Activity",
                severity=ThreatSeverity.LOW,
                tactic=MITRETactic.DISCOVERY,
                technique_id="T1033",
                process_regex=re.compile(r"^whoami(\.exe)?$", re.IGNORECASE),
                command_regex=re.compile(r"\/(all|priv|groups)", re.IGNORECASE),
            ),
        ])

    def evaluate_event(self, event: ProcessEvent) -> List[ThreatAlert]:
        """Run all active rules against event."""
        alerts: List[ThreatAlert] = []
        for rule in self.rules:
            if rule.evaluate(event):
                alerts.append(
                    ThreatAlert(
                        alert_id=f"ALT_{rule.rule_id}_{event.pid}",
                        rule_name=rule.title,
                        severity=rule.severity,
                        tactic=rule.tactic,
                        technique_id=rule.technique_id,
                        pid=event.pid,
                        ppid=event.ppid,
                        process_name=event.process_name,
                        command_line=event.command_line,
                        parent_name=event.parent_name,
                        evidence=f"Matched Sigma Rule '{rule.title}' ({rule.rule_id}).",
                    )
                )
        return alerts
