"""
Unit tests for the SentinelEngine coordinator, incident reporting, and STIX 2.1 CTI export.
"""

from sentineltrace.engine import SentinelEngine
from sentineltrace.types import ProcessEvent, ProcessEventType, ThreatSeverity


def test_engine_incident_report_and_stix_export():
    """Verify end-to-end event ingestion, incident generation, and STIX 2.1 serialization."""
    engine = SentinelEngine()

    # 1. Macro execution
    ev1 = ProcessEvent(
        event_id="EVT_MACRO_1",
        event_type=ProcessEventType.PROCESS_START,
        pid=3000,
        ppid=1500,
        process_name="powershell.exe",
        image_path="C:\\Windows\\powershell.exe",
        command_line="powershell.exe -w hidden script.ps1",
        parent_name="WINWORD.EXE",
        user="CORP\\victim",
    )
    alerts1 = engine.ingest_event(ev1)
    assert len(alerts1) >= 1

    # 2. Ransomware shadow copy delete
    ev2 = ProcessEvent(
        event_id="EVT_VSS_1",
        event_type=ProcessEventType.PROCESS_START,
        pid=4000,
        ppid=3000,
        process_name="vssadmin.exe",
        image_path="C:\\Windows\\vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet",
        parent_name="powershell.exe",
        user="CORP\\victim",
    )
    alerts2 = engine.ingest_event(ev2)
    assert len(alerts2) >= 1

    # Generate incident report
    report = engine.generate_incident_report()
    assert report["events_processed"] == 2
    assert report["total_alerts"] >= 2
    assert report["highest_severity"] == ThreatSeverity.CRITICAL.name
    assert report["chain_verified"] is True

    # Export STIX 2.1
    stix = engine.export_stix2()
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) > 0

    # Ensure attack-pattern and indicator objects exist
    types_in_bundle = {obj["type"] for obj in stix["objects"]}
    assert "attack-pattern" in types_in_bundle
    assert "indicator" in types_in_bundle
    assert "relationship" in types_in_bundle
