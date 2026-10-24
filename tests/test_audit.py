"""
Unit tests for the cryptographic forensic timeline audit chain.
"""

import pytest

from sentineltrace.audit import ForensicAuditChain, GENESIS_FORENSIC_ROOT
from sentineltrace.types import MITRETactic, ProcessEvent, ProcessEventType, ThreatAlert, ThreatSeverity


def test_forensic_chain_continuous_hashing():
    """Verify that events create an unbroken, continuous SHA-256 timeline."""
    chain = ForensicAuditChain()
    assert chain.current_hash == GENESIS_FORENSIC_ROOT

    ev1 = ProcessEvent(
        event_id="EVT_CH_1",
        event_type=ProcessEventType.PROCESS_START,
        pid=1000,
        ppid=4,
        process_name="cmd.exe",
        image_path="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe",
        parent_name="explorer.exe",
        user="CORP\\user",
        timestamp_ns=1000000,
    )
    hash1 = chain.record_process_event(ev1)
    assert hash1 != GENESIS_FORENSIC_ROOT
    assert chain.current_hash == hash1
    assert len(chain.timeline) == 1

    ev2 = ProcessEvent(
        event_id="EVT_CH_2",
        event_type=ProcessEventType.PROCESS_TERMINATE,
        pid=1000,
        ppid=4,
        process_name="cmd.exe",
        image_path="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe",
        parent_name="explorer.exe",
        user="CORP\\user",
        timestamp_ns=2000000,
    )
    hash2 = chain.record_process_event(ev2)
    assert hash2 != hash1
    assert len(chain.timeline) == 2

    # Verify unbroken integrity
    assert chain.verify_integrity() is True


def test_forensic_chain_detects_evidence_tampering():
    """Verify that an altered historical node in the forensic timeline raises ValueError."""
    chain = ForensicAuditChain()
    ev = ProcessEvent(
        event_id="EVT_TAMPER_TARGET",
        event_type=ProcessEventType.PROCESS_START,
        pid=2000,
        ppid=1000,
        process_name="powershell.exe",
        image_path="C:\\Windows\\powershell.exe",
        command_line="powershell.exe -enc BAD_PAYLOAD",
        parent_name="cmd.exe",
        user="CORP\\user",
        timestamp_ns=1000,
    )
    chain.record_process_event(ev)

    # Attacker tampers with the node digest in memory / log
    corrupted_node = chain.timeline[0]
    # Replace node with tampered digest
    tampered_node = type(corrupted_node)(
        sequence=corrupted_node.sequence,
        event_id=corrupted_node.event_id,
        event_category=corrupted_node.event_category,
        item_digest="0000000000000000000000000000000000000000000000000000000000000000",
        prev_hash=corrupted_node.prev_hash,
        current_hash=corrupted_node.current_hash,
        timestamp_ns=corrupted_node.timestamp_ns,
    )
    chain.timeline[0] = tampered_node

    with pytest.raises(ValueError) as exc_info:
        chain.verify_integrity()

    assert "Forensic Evidence Tampering Detected" in str(exc_info.value)
