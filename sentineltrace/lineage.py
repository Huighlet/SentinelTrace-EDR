"""
SentinelTrace-EDR: Process Lineage Directed Acyclic Graph (DAG) & Behavioral Detectors.
Maintains parent-child process ancestry trees and flags anomalous LOLBin execution chains.
"""

from __future__ import annotations

import dataclasses
import re
import threading
from typing import Dict, List, Optional, Set

from sentineltrace.types import MITRETactic, ProcessEvent, ProcessEventType, ThreatAlert, ThreatSeverity

OFFICE_BINARIES: Set[str] = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"
}

WEB_SERVER_BINARIES: Set[str] = {
    "w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "apache2.exe", "php-cgi.exe"
}

SHELL_LOLBINS: Set[str] = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "certutil.exe", "bash.exe", "sh.exe"
}

RANSOMWARE_WIPE_PATTERNS = [
    re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE),
    re.compile(r"wmic(\.exe)?\s+shadowcopy\s+delete", re.IGNORECASE),
    re.compile(r"wbadmin(\.exe)?\s+delete\s+catalog", re.IGNORECASE),
    re.compile(r"bcdedit(\.exe)?\s+/set\s+.*recoveryenabled\s+no", re.IGNORECASE),
]

LSASS_DUMP_PATTERNS = [
    re.compile(r"comsvcs(\.dll)?\s+.*#?24\s+", re.IGNORECASE),
    re.compile(r"comsvcs(\.dll)?\s+.*minidump", re.IGNORECASE),
    re.compile(r"procdump(\.exe)?\s+.*lsass", re.IGNORECASE),
    re.compile(r"rundll32(\.exe)?\s+.*comsvcs(\.dll)?.*lsass", re.IGNORECASE),
]


@dataclasses.dataclass(slots=True)
class ProcessNode:
    """Node representing an executed host process within the lineage tree."""
    pid: int
    ppid: int
    process_name: str
    command_line: str
    image_path: str
    user: str
    sha256: str
    start_time_ns: int
    end_time_ns: Optional[int] = None
    is_active: bool = True
    parent: Optional[ProcessNode] = None
    children: List[ProcessNode] = dataclasses.field(default_factory=list)


class ProcessLineageGraph:
    """
    In-Memory Process DAG Tracking Process Hierarchy.
    """
    def __init__(self) -> None:
        self._nodes: Dict[int, ProcessNode] = {}
        self._lock = threading.Lock()

    def register_start(self, event: ProcessEvent) -> ProcessNode:
        """Register newly started process, resolving and attaching to parent."""
        with self._lock:
            parent_node = self._nodes.get(event.ppid)

            node = ProcessNode(
                pid=event.pid,
                ppid=event.ppid,
                process_name=event.process_name.lower(),
                command_line=event.command_line,
                image_path=event.image_path,
                user=event.user,
                sha256=event.sha256,
                start_time_ns=event.timestamp_ns,
                parent=parent_node,
            )

            if parent_node is not None:
                parent_node.children.append(node)

            self._nodes[event.pid] = node
            return node

    def register_terminate(self, pid: int, timestamp_ns: int) -> Optional[ProcessNode]:
        """Mark process as terminated."""
        with self._lock:
            node = self._nodes.get(pid)
            if node is not None:
                node.is_active = False
                node.end_time_ns = timestamp_ns
            return node

    def get_ancestry(self, pid: int) -> List[ProcessNode]:
        """Walk up the DAG to return list of ancestors from current process up to root."""
        with self._lock:
            lineage: List[ProcessNode] = []
            current = self._nodes.get(pid)
            visited = set()

            while current is not None and current.pid not in visited:
                lineage.append(current)
                visited.add(current.pid)
                current = current.parent

            return lineage

    def detect_anomalies(self, event: ProcessEvent) -> List[ThreatAlert]:
        """
        Evaluate behavioral lineage rules against a process creation event.
        Returns list of emitted ThreatAlerts.
        """
        alerts: List[ThreatAlert] = []
        proc_name = event.process_name.lower()
        parent_name = event.parent_name.lower()
        cmd = event.command_line

        # 1. Office Macro Scripting LOLBin Spawn Detector
        if parent_name in OFFICE_BINARIES and proc_name in SHELL_LOLBINS:
            alerts.append(
                ThreatAlert(
                    alert_id=f"ALT_MACRO_{event.pid}",
                    rule_name="Suspicious Office Macro Child Process",
                    severity=ThreatSeverity.CRITICAL,
                    tactic=MITRETactic.INITIAL_ACCESS,
                    technique_id="T1566.001",
                    pid=event.pid,
                    ppid=event.ppid,
                    process_name=event.process_name,
                    command_line=event.command_line,
                    parent_name=event.parent_name,
                    evidence=f"Office application '{parent_name}' spawned scripting shell '{proc_name}'.",
                )
            )

        # 2. Web Server WebShell Spawn Detector
        if parent_name in WEB_SERVER_BINARIES and proc_name in SHELL_LOLBINS:
            alerts.append(
                ThreatAlert(
                    alert_id=f"ALT_WEBSHELL_{event.pid}",
                    rule_name="Web Server Spawned Interactive Shell (WebShell)",
                    severity=ThreatSeverity.CRITICAL,
                    tactic=MITRETactic.PERSISTENCE,
                    technique_id="T1505.003",
                    pid=event.pid,
                    ppid=event.ppid,
                    process_name=event.process_name,
                    command_line=event.command_line,
                    parent_name=event.parent_name,
                    evidence=f"Production web server worker '{parent_name}' spawned shell '{proc_name}'.",
                )
            )

        # 3. Ransomware Shadow Copy Wiping Detector
        for pat in RANSOMWARE_WIPE_PATTERNS:
            if pat.search(cmd):
                alerts.append(
                    ThreatAlert(
                        alert_id=f"ALT_RANSOM_{event.pid}",
                        rule_name="Ransomware Shadow Copy Deletion (Inhibit Recovery)",
                        severity=ThreatSeverity.CRITICAL,
                        tactic=MITRETactic.IMPACT,
                        technique_id="T1490",
                        pid=event.pid,
                        ppid=event.ppid,
                        process_name=event.process_name,
                        command_line=event.command_line,
                        parent_name=event.parent_name,
                        evidence=f"Process executed command to destroy volume shadow recovery: '{cmd}'.",
                    )
                )
                break

        # 4. LSASS Credential Memory Dump Detector
        for pat in LSASS_DUMP_PATTERNS:
            if pat.search(cmd):
                alerts.append(
                    ThreatAlert(
                        alert_id=f"ALT_LSASS_{event.pid}",
                        rule_name="OS Credential Dumping: LSASS Memory MiniDump",
                        severity=ThreatSeverity.CRITICAL,
                        tactic=MITRETactic.CREDENTIAL_ACCESS,
                        technique_id="T1003.001",
                        pid=event.pid,
                        ppid=event.ppid,
                        process_name=event.process_name,
                        command_line=event.command_line,
                        parent_name=event.parent_name,
                        evidence=f"Process executed memory dumping command targeting LSASS: '{cmd}'.",
                    )
                )
                break

        return alerts
