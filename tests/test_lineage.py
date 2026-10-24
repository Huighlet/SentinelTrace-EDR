"""
Unit tests for the Process Lineage Directed Acyclic Graph (DAG) and ancestry resolution.
"""

from sentineltrace.lineage import ProcessLineageGraph
from sentineltrace.types import ProcessEvent, ProcessEventType


def test_process_dag_parent_child_resolution():
    """Verify that process creation correctly establishes parent-child DAG links."""
    graph = ProcessLineageGraph()

    # Root: explorer.exe (PID 1000, PPID 4)
    ev_root = ProcessEvent(
        event_id="EVT_1",
        event_type=ProcessEventType.PROCESS_START,
        pid=1000,
        ppid=4,
        process_name="explorer.exe",
        image_path="C:\\Windows\\explorer.exe",
        command_line="C:\\Windows\\explorer.exe",
        parent_name="System",
        user="CORP\\user",
    )
    node_root = graph.register_start(ev_root)
    assert node_root.pid == 1000
    assert node_root.parent is None

    # Child: cmd.exe (PID 2000, PPID 1000)
    ev_child = ProcessEvent(
        event_id="EVT_2",
        event_type=ProcessEventType.PROCESS_START,
        pid=2000,
        ppid=1000,
        process_name="cmd.exe",
        image_path="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe",
        parent_name="explorer.exe",
        user="CORP\\user",
    )
    node_child = graph.register_start(ev_child)
    assert node_child.parent is not None
    assert node_child.parent.pid == 1000
    assert len(node_root.children) == 1
    assert node_root.children[0].pid == 2000

    # Grandchild: whoami.exe (PID 3000, PPID 2000)
    ev_grandchild = ProcessEvent(
        event_id="EVT_3",
        event_type=ProcessEventType.PROCESS_START,
        pid=3000,
        ppid=2000,
        process_name="whoami.exe",
        image_path="C:\\Windows\\System32\\whoami.exe",
        command_line="whoami.exe",
        parent_name="cmd.exe",
        user="CORP\\user",
    )
    graph.register_start(ev_grandchild)

    # Verify ancestry traversal
    ancestry = graph.get_ancestry(3000)
    assert len(ancestry) == 3
    assert [n.pid for n in ancestry] == [3000, 2000, 1000]


def test_process_termination_state():
    """Verify termination marks node inactive and logs end time."""
    graph = ProcessLineageGraph()
    ev = ProcessEvent(
        event_id="EVT_10",
        event_type=ProcessEventType.PROCESS_START,
        pid=5000,
        ppid=1000,
        process_name="notepad.exe",
        image_path="C:\\Windows\\notepad.exe",
        command_line="notepad.exe",
        parent_name="explorer.exe",
        user="CORP\\user",
        timestamp_ns=1000,
    )
    graph.register_start(ev)
    term_node = graph.register_terminate(5000, timestamp_ns=2000)

    assert term_node is not None
    assert term_node.is_active is False
    assert term_node.end_time_ns == 2000
