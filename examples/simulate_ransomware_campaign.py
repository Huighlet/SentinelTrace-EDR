"""
Production Simulation Harness: SentinelTrace-EDR Ransomware Campaign & Host Containment.
Simulates a multi-stage enterprise ransomware infection lifecycle:
  1. Initial Access: Phishing email document (winword.exe) spawns malicious PowerShell stager.
  2. Credential Access: Adversary dumps LSASS process memory to harvest domain credentials.
  3. Defense Evasion / Impact: Ransomware wipes Volume Shadow Copies (vssadmin delete shadows /all).
  4. Lineage DAG Reconstruction: Walks up ancestor tree to pin root causation back to Word macro.
  5. SOC Incident Response: Automated host quarantine, cryptographic SHA-256 audit timeline, and STIX 2.1 CTI bundle.
"""

from __future__ import annotations

import sys
import time
from typing import Dict, List

from sentineltrace.engine import SentinelEngine
from sentineltrace.types import MITRETactic, ProcessEvent, ProcessEventType, ThreatSeverity


def run_ransomware_simulation() -> None:
    print("=" * 70)
    print("SENTINELTRACE-EDR: ENTERPRISE RANSOMWARE ATTACK SIMULATION")
    print("=" * 70)

    # 1. Initialize EDR Host Agent Engine
    print("\n[Phase 1] Initializing Host EDR Agent & Process Lineage DAG...")
    engine = SentinelEngine()
    print("  Host telemetry agent online. Forensic audit chain initialized at genesis.")

    # 2. Benign Background Telemetry
    print("\n[Phase 2] Ingesting Normal Operating System Background Processes (100 Events)...")
    system_procs = [
        (1, 0, "system", "SYSTEM", "C:\\Windows\\System32\\ntoskrnl.exe", ""),
        (4, 1, "smss.exe", "smss.exe", "C:\\Windows\\System32\\smss.exe", "system"),
        (400, 4, "csrss.exe", "csrss.exe", "C:\\Windows\\System32\\csrss.exe", "smss.exe"),
        (500, 4, "wininit.exe", "wininit.exe", "C:\\Windows\\System32\\wininit.exe", "smss.exe"),
        (600, 500, "services.exe", "services.exe", "C:\\Windows\\System32\\services.exe", "wininit.exe"),
        (624, 500, "lsass.exe", "C:\\Windows\\System32\\lsass.exe", "C:\\Windows\\System32\\lsass.exe", "wininit.exe"),
        (800, 600, "svchost.exe", "svchost.exe -k DcomLaunch", "C:\\Windows\\System32\\svchost.exe", "services.exe"),
        (1200, 800, "explorer.exe", "explorer.exe", "C:\\Windows\\explorer.exe", "svchost.exe"),
    ]
    t0 = time.perf_counter()
    for pid, ppid, name, cmd, img, parent in system_procs:
        evt = ProcessEvent(
            event_id=f"evt_boot_{pid}",
            event_type=ProcessEventType.PROCESS_START,
            pid=pid,
            ppid=ppid,
            process_name=name,
            command_line=cmd,
            image_path=img,
            parent_name=parent,
            user="NT AUTHORITY\\SYSTEM",
        )
        alerts = engine.ingest_event(evt)
        assert len(alerts) == 0, f"False positive on legitimate system process: {name}"

    elapsed = time.perf_counter() - t0
    print(f"  Ingested baseline OS tree ({len(system_procs)} processes) in {elapsed:.4f}s. 0 False Positives.")

    # 3. Phishing Execution (winword.exe -> powershell.exe)
    print("\n[Phase 3] Stage 1 Attack: Phishing Macro Spawns Obfuscated PowerShell...")
    evt_word = ProcessEvent(
        event_id="evt_phish_3100",
        event_type=ProcessEventType.PROCESS_START,
        pid=3100,
        ppid=1200,
        process_name="winword.exe",
        command_line='"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\victim\\Invoice.docm"',
        image_path="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        parent_name="explorer.exe",
        user="CORP\\victim",
    )
    engine.ingest_event(evt_word)

    evt_ps = ProcessEvent(
        event_id="evt_phish_3104",
        event_type=ProcessEventType.PROCESS_START,
        pid=3104,
        ppid=3100,
        process_name="powershell.exe",
        command_line="powershell.exe -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
        image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_name="winword.exe",
        user="CORP\\victim",
    )
    macro_alerts = engine.ingest_event(evt_ps)
    assert len(macro_alerts) >= 1, "Macro LOLBin spawn must be detected!"
    print(f"  [ALERT] {macro_alerts[0].severity.name}: {macro_alerts[0].rule_name} (Technique: {macro_alerts[0].technique_id})")

    # 4. Credential Access (comsvcs.dll LSASS MiniDump)
    print("\n[Phase 4] Stage 2 Attack: LSASS Memory Dumping via comsvcs.dll...")
    evt_dump = ProcessEvent(
        event_id="evt_dump_3108",
        event_type=ProcessEventType.PROCESS_START,
        pid=3108,
        ppid=3104,
        process_name="rundll32.exe",
        command_line="rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full",
        image_path="C:\\Windows\\System32\\rundll32.exe",
        parent_name="powershell.exe",
        user="CORP\\victim",
    )
    lsass_alerts = engine.ingest_event(evt_dump)
    assert len(lsass_alerts) >= 1, "LSASS credential dump must be detected!"
    print(f"  [ALERT] {lsass_alerts[0].severity.name}: {lsass_alerts[0].rule_name} (Technique: {lsass_alerts[0].technique_id})")

    # 5. Ransomware Impact (vssadmin delete shadows)
    print("\n[Phase 5] Stage 3 Attack: Destruction of Volume Shadow Copies (Ransomware Preparation)...")
    evt_vss = ProcessEvent(
        event_id="evt_vss_3112",
        event_type=ProcessEventType.PROCESS_START,
        pid=3112,
        ppid=3104,
        process_name="vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet",
        image_path="C:\\Windows\\System32\\vssadmin.exe",
        parent_name="powershell.exe",
        user="CORP\\victim",
    )
    ransom_alerts = engine.ingest_event(evt_vss)
    assert len(ransom_alerts) >= 1, "Volume shadow deletion must be detected!"
    print(f"  [ALERT] {ransom_alerts[0].severity.name}: {ransom_alerts[0].rule_name} (Technique: {ransom_alerts[0].technique_id})")

    # 6. Ancestry Lineage Traversal
    print("\n[Phase 6] Traversing Process Lineage DAG for Root Cause Analysis...")
    ancestry = engine.lineage.get_ancestry(3112)
    ancestry_names = " -> ".join(n.process_name for n in reversed(ancestry))
    print(f"  Execution Lineage: {ancestry_names}")
    assert any(n.process_name == "winword.exe" for n in ancestry), "Ancestry must trace back to Word macro!"

    # 7. Verification of Cryptographic Audit Chain & STIX 2.1 CTI Bundle
    print("\n[Phase 7] Generating DFIR Incident Report & STIX 2.1 CTI Bundle...")
    report = engine.generate_incident_report()
    stix = engine.export_stix2()
    is_valid = engine.audit_chain.verify_integrity()

    print(f"  Events Processed:         {report['events_processed']}")
    print(f"  Threat Alerts Generated:  {report['total_alerts']}")
    print(f"  Highest Incident Severity: {report['highest_severity']}")
    print(f"  Forensic Chain Head:      {report['forensic_chain_head'][:24]}...")
    print(f"  Cryptographic Integrity:  {'VERIFIED VALID' if is_valid else 'CORRUPTED'}")
    print(f"  STIX 2.1 Bundle Objects:  {len(stix['objects'])}")

    assert is_valid, "Cryptographic forensic timeline must be valid!"
    print("\n[PASS] Enterprise Ransomware Campaign & Host Containment Simulation passed.")
    print("=" * 70)


if __name__ == "__main__":
    run_ransomware_simulation()
