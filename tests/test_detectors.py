"""
Unit tests for host behavioral anomaly detectors (Office Macros, WebShells, Ransomware, LSASS).
"""

from sentineltrace.lineage import ProcessLineageGraph
from sentineltrace.types import MITRETactic, ProcessEvent, ProcessEventType, ThreatSeverity


def test_office_macro_lolbin_spawn():
    """Verify WINWORD.EXE spawning powershell.exe triggers CRITICAL initial access alert."""
    graph = ProcessLineageGraph()
    ev = ProcessEvent(
        event_id="EVT_MACRO",
        event_type=ProcessEventType.PROCESS_START,
        pid=2500,
        ppid=1200,
        process_name="powershell.exe",
        image_path="C:\\Windows\\System32\\powershell.exe",
        command_line="powershell.exe -ep bypass -file script.ps1",
        parent_name="WINWORD.EXE",
        user="CORP\\victim",
    )
    alerts = graph.detect_anomalies(ev)
    assert len(alerts) == 1
    assert alerts[0].severity == ThreatSeverity.CRITICAL
    assert alerts[0].tactic == MITRETactic.INITIAL_ACCESS
    assert alerts[0].technique_id == "T1566.001"


def test_webshell_interactive_shell_spawn():
    """Verify IIS web worker w3wp.exe spawning cmd.exe triggers CRITICAL WebShell alert."""
    graph = ProcessLineageGraph()
    ev = ProcessEvent(
        event_id="EVT_WS",
        event_type=ProcessEventType.PROCESS_START,
        pid=4000,
        ppid=800,
        process_name="cmd.exe",
        image_path="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c whoami",
        parent_name="w3wp.exe",
        user="IIS APPPOOL\\DefaultAppPool",
    )
    alerts = graph.detect_anomalies(ev)
    assert len(alerts) == 1
    assert alerts[0].severity == ThreatSeverity.CRITICAL
    assert alerts[0].tactic == MITRETactic.PERSISTENCE
    assert alerts[0].technique_id == "T1505.003"


def test_ransomware_shadow_copy_wipe():
    """Verify vssadmin delete shadows command triggers CRITICAL Impact alert."""
    graph = ProcessLineageGraph()
    ev = ProcessEvent(
        event_id="EVT_VSS",
        event_type=ProcessEventType.PROCESS_START,
        pid=5500,
        ppid=3000,
        process_name="vssadmin.exe",
        image_path="C:\\Windows\\System32\\vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet",
        parent_name="cmd.exe",
        user="NT AUTHORITY\\SYSTEM",
    )
    alerts = graph.detect_anomalies(ev)
    assert len(alerts) == 1
    assert alerts[0].severity == ThreatSeverity.CRITICAL
    assert alerts[0].tactic == MITRETactic.IMPACT
    assert alerts[0].technique_id == "T1490"


def test_lsass_memory_dump():
    """Verify comsvcs.dll minidump targeting LSASS triggers CRITICAL Credential Access alert."""
    graph = ProcessLineageGraph()
    ev = ProcessEvent(
        event_id="EVT_LSASS",
        event_type=ProcessEventType.PROCESS_START,
        pid=6000,
        ppid=3000,
        process_name="rundll32.exe",
        image_path="C:\\Windows\\System32\\rundll32.exe",
        command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 lsass.dmp full",
        parent_name="cmd.exe",
        user="NT AUTHORITY\\SYSTEM",
    )
    alerts = graph.detect_anomalies(ev)
    assert len(alerts) == 1
    assert alerts[0].severity == ThreatSeverity.CRITICAL
    assert alerts[0].tactic == MITRETactic.CREDENTIAL_ACCESS
    assert alerts[0].technique_id == "T1003.001"
