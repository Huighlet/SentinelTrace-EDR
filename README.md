# SentinelTrace-EDR

Lightweight Host-Level Behavioural Threat Detection and Cryptographic Forensic Timeline Engine.

Designed for Enterprise Security Operations Centers (SOCs), Incident Response (IR) teams, and Critical Information Infrastructure (CII) regulators. Built from first principles to track host process lineage as a Directed Acyclic Graph (DAG), detect Living-off-the-Land (LOLBin) attack chains, evaluate declarative Sigma rules, and generate tamper-evident, court-admissible forensic timelines using cryptographic SHA-256 state chains.

---

## 1. Problem Statement: The Evasion of Signature Anti-Virus

Modern adversaries bypass conventional file-signature antivirus (AV) by executing fileless attacks and abusing legitimate, digitally-signed operating system binaries (Living-off-the-Land Binaries, or LOLBins):

```
+----------------------------------------------------------------------------------------------------+
|                               HOST-LEVEL ATTACK MATRIX                                             |
+----------------------------------------------------------------------------------------------------+
| Threat Vector             | LOLBin Execution                       | Defense in SentinelTrace-EDR  |
+---------------------------+----------------------------------------+-------------------------------+
| Phishing Document Macros  | WINWORD.EXE -> powershell.exe -enc...  | Process Lineage DAG anomaly   |
| (T1566.001 Initial Access)| Spawns scripting shell from office app | parent-child invariant filter |
+---------------------------+----------------------------------------+-------------------------------+
| Persistent WebShells      | w3wp.exe (IIS) -> cmd.exe /c whoami    | Web server worker child       |
| (T1505.003 Persistence)   | Spawns interactive shell from web root | process violation alert       |
+---------------------------+----------------------------------------+-------------------------------+
| Ransomware Shadow Wipe    | vssadmin.exe delete shadows /all /quiet| Command-line regex detection  |
| (T1490 Inhibit Recovery)  | Destroys volume backup before encrypt  | mapped to MITRE Impact T1490  |
+---------------------------+----------------------------------------+-------------------------------+
| Credential Harvesting     | rundll32.exe comsvcs.dll, MiniDump     | LSASS memory handle access    |
| (T1003.001 Cred Access)   | Dumps LSASS process memory to disk     | pattern match and mitigation  |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Core Detection & Forensic Primitives

### 1. Process Lineage Directed Acyclic Graph (DAG)

SentinelTrace maintains an in-memory process tree where every process execution event is attached to its parent process node:

```
[System (PID: 4)]
       |
[explorer.exe (PID: 1000)]
       |
[WINWORD.EXE (PID: 2040)] <--- (User opens phishing invoice)
       |
[powershell.exe (PID: 3100)] <--- [ALERT: T1566.001 Macro Spawn]
       |
       +---> [certutil.exe (PID: 3250)] <--- [ALERT: T1105 Tool Transfer]
       |
       +---> [vssadmin.exe (PID: 3550)] <--- [ALERT: T1490 Shadow Copy Wipe]
       |
       +---> [rundll32.exe (PID: 3700)] <--- [ALERT: T1003.001 LSASS MiniDump]
```

### 2. Cryptographic Forensic Audit Chain (Non-Repudiation)

During regulatory incident notifications (such as Ghana Cyber Security Authority Act 1038 or ISO 27001 forensics) or court proceedings, attackers or malicious insiders can claim log files were retroactively altered.

SentinelTrace anchors every event and detection into a recursive SHA-256 state chain:

$$H_0 = \text{SHA256}(\text{"SENTINEL\_TRACE\_FORENSIC\_ROOT\_V1"})$$

$$H_t = \text{SHA256}\Big( H_{t-1} \parallel \text{Seq}_t \parallel \text{Category}_t \parallel \text{EventDigest}_t \parallel \text{Timestamp}_t \Big)$$

Any retroactive alteration of command lines, PIDs, timestamps, or alerts breaks the cryptographic chain mathematically.

### 3. STIX 2.1 Threat Intelligence Export

Detections are automatically serializable into structured STIX 2.1 Cyber Threat Intelligence (CTI) JSON bundles containing `attack-pattern`, `indicator`, and `relationship` entities for automated SIEM ingestion (Splunk, Elastic, Sentinel).

---

## 3. Architecture & Data Flow

```
                      HOST OS TELEMETRY INGRESS
                  (Process Starts, Terminations, CLI)
                                     |
                                     v
                 +---------------------------------------+
                 |    Process Lineage DAG Coordinator    |
                 |  - Parent-Child Attachment (PID/PPID) |
                 |  - Active Process State Tracking      |
                 +---------------------------------------+
                                     |
                    +----------------+----------------+
                    |                                 |
                    v                                 v
   +---------------------------------+   +---------------------------------+
   |   Behavioral Lineage Detectors  |   |    Declarative Sigma Engine     |
   | - Office Macro LOLBin Spawns    |   | - Ingress Tool Transfer (T1105) |
   | - WebShell Process Invariants   |   | - Obfuscated Encoded PowerShell |
   | - Ransomware Shadow Wipes       |   | - Local Admin User Creation     |
   | - LSASS Memory MiniDump Access  |   | - Registry Run Key Persistence  |
   +---------------------------------+   +---------------------------------+
                    \                                 /
                     \                               /
                      +--------------+--------------+
                                     |
                                     v
                 +---------------------------------------+
                 |   Cryptographic Forensic State Chain  |
                 |  - SHA-256 Chained Event Timeline     |
                 |  - Non-Repudiation Integrity Proof    |
                 +---------------------------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |    Incident Report & STIX 2.1 Export  |
                 +---------------------------------------+
```

---

## 4. Performance Benchmarks

Micro-benchmarks executed on commodity 64-bit hardware (Python 3.13):

```text
=================================================================
SENTINELTRACE-EDR BENCHMARK: 50,000 EVENTS
=================================================================
Total Ingestion Time:       1.898 seconds
Evaluation Throughput:      26,344.3 events / second
Forensic Chain Nodes:       50,000
Chain Integrity Check:      True
=================================================================
```

* **Lineage & Rule Processing Throughput:** Evaluates process creation events, maintains DAG hierarchy, and updates cryptographic forensic chains at **26,344 events per second**.

---

## 5. Project Map

```
SentinelTrace-EDR/
|-- sentineltrace/
|   |-- __init__.py         # Public exports and API surface
|   |-- types.py            # ProcessEvent, ThreatAlert, MITRETactic, Severity
|   |-- lineage.py          # Process Lineage DAG and behavioral anomaly detectors
|   |-- rules.py            # Declarative Sigma-style threat hunting rule engine
|   |-- audit.py            # Cryptographic SHA-256 forensic timeline audit chain
|   |-- engine.py           # SentinelEngine coordinator and STIX 2.1 serializer
|   |-- cli.py              # CLI for attack simulation, STIX export, benchmarks
|-- tests/
|   |-- test_lineage.py     # DAG resolution, ancestry walk, process termination
|   |-- test_detectors.py   # Macro, WebShell, Ransomware, LSASS dump detectors
|   |-- test_rules.py       # Sigma rule evaluations and benign clean checks
|   |-- test_audit.py       # SHA-256 forensic timeline and tamper detection
|   |-- test_engine.py      # End-to-end incident generation and STIX 2.1 bundle
|-- pyproject.toml          # Package metadata and CLI executable hook
|-- requirements.txt        # Frozen dependencies
|-- LICENSE                 # MIT License (Huighlet Eyram Zowonu)
|-- README.md               # Technical specification and documentation
```

---

## 6. Installation & Quickstart

### Setup Environment

```bash
git clone https://github.com/Huighlet/SentinelTrace-EDR.git
cd SentinelTrace-EDR

python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows:
.\.venv\Scripts\Activate.ps1

pip install -e .
```

### Python API Example

```python
from sentineltrace import SentinelEngine, ProcessEvent, ProcessEventType

engine = SentinelEngine()

# Ingest process creation event
event = ProcessEvent(
    event_id="EVT_001",
    event_type=ProcessEventType.PROCESS_START,
    pid=3100,
    ppid=2040,
    process_name="powershell.exe",
    image_path="C:\\Windows\\System32\\powershell.exe",
    command_line="powershell.exe -w hidden -enc JABjAGwAYQBzAHMA...",
    parent_name="WINWORD.EXE",
    user="CORP\\jdoe",
)

alerts = engine.ingest_event(event)
for alert in alerts:
    print(f"[{alert.severity.name}] {alert.rule_name} (MITRE: {alert.technique_id})")

# Export STIX 2.1 Cyber Threat Intelligence bundle
stix_bundle = engine.export_stix2()
print(f"Generated STIX 2.1 Bundle: {stix_bundle['id']}")
```

---

## 7. CLI Usage

### 1. Run Multi-Stage Cyber Attack Simulation

Simulates an end-to-end kill chain: Phishing Macro -> Obfuscated PowerShell -> Certutil Ingress -> User Reconnaissance -> Ransomware Shadow Copy Wipe -> LSASS Credential Dump:

```bash
sentineltrace simulate
```

Output:
```text
=================================================================
SENTINELTRACE-EDR: MULTI-STAGE ATTACK CHAIN SIMULATION
=================================================================
[*] Processing Event: explorer.exe (PID: 1000, PPID: 4)
[*] Processing Event: WINWORD.EXE (PID: 2040, PPID: 1000)
[*] Processing Event: powershell.exe (PID: 3100, PPID: 2040)
    [ALERT] CRITICAL | Suspicious Office Macro Child Process [T1566.001]
            Detail: Office application 'winword.exe' spawned scripting shell 'powershell.exe'.
    [ALERT] HIGH | Obfuscated PowerShell Encoded Command Execution [T1059.001]
            Detail: Matched Sigma Rule 'Obfuscated PowerShell Encoded Command Execution' (SIG_002).
[*] Processing Event: certutil.exe (PID: 3250, PPID: 3100)
    [ALERT] HIGH | Certutil Suspicious Ingress File Download [T1105]
            Detail: Matched Sigma Rule 'Certutil Suspicious Ingress File Download' (SIG_001).
[*] Processing Event: whoami.exe (PID: 3400, PPID: 3100)
    [ALERT] LOW | Privilege and User Discovery Activity [T1033]
            Detail: Matched Sigma Rule 'Privilege and User Discovery Activity' (SIG_005).
[*] Processing Event: vssadmin.exe (PID: 3550, PPID: 3100)
    [ALERT] CRITICAL | Ransomware Shadow Copy Deletion (Inhibit Recovery) [T1490]
            Detail: Process executed command to destroy volume shadow recovery: 'vssadmin.exe delete shadows /all /quiet'.
[*] Processing Event: rundll32.exe (PID: 3700, PPID: 3100)
    [ALERT] CRITICAL | OS Credential Dumping: LSASS Memory MiniDump [T1003.001]
            Detail: Process executed memory dumping command targeting LSASS: 'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\Public\lsass.dmp full'.
-----------------------------------------------------------------
INCIDENT REPORT SUMMARY
Total Telemetry Events:     7
Total Detections Emitted:   6
Highest Threat Severity:    CRITICAL
Forensic Chain Length:      13 chained nodes
Forensic Chain Head Hash:   7c8dd689a63672bf...
Forensic Integrity Verified:True
=================================================================
```

### 2. Run High-Load Ingestion Micro-Benchmark

```bash
sentineltrace bench -n 50000
```

---

## 8. Test Suite Execution

Run the complete 12-case test suite covering DAG ancestry resolution, LOLBin detectors, Sigma rules, and cryptographic audit tampering:

```bash
pytest -v
```

All 12 test scenarios pass deterministically:
```text
tests/test_audit.py::test_forensic_chain_continuous_hashing PASSED
tests/test_audit.py::test_forensic_chain_detects_evidence_tampering PASSED
tests/test_detectors.py::test_office_macro_lolbin_spawn PASSED
tests/test_detectors.py::test_webshell_interactive_shell_spawn PASSED
tests/test_detectors.py::test_ransomware_shadow_copy_wipe PASSED
tests/test_detectors.py::test_lsass_memory_dump PASSED
tests/test_engine.py::test_engine_incident_report_and_stix_export PASSED
tests/test_lineage.py::test_process_dag_parent_child_resolution PASSED
tests/test_lineage.py::test_process_termination_state PASSED
tests/test_rules.py::test_sigma_certutil_download_rule PASSED
tests/test_rules.py::test_sigma_powershell_encoded_rule PASSED
tests/test_rules.py::test_sigma_benign_command_clean PASSED
```

---

## 9. License

MIT License. Copyright (c) 2026 Huighlet Eyram Zowonu.
