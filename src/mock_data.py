"""
mock_data.py
------------
Pre-packaged, synthetic SOC telemetry so the whole system runs instantly
with zero external SIEM / EDR / cloud dependencies.

Three telemetry families are provided, matching common SOC data sources:
  - Windows Security Event Log entries (4624/4688/4672 style)
  - Sysmon events (process creation, network connection, image load)
  - Suricata EVE JSON alerts (signature-based network IDS)

Each fixture is keyed by a synthetic `incident_id` so `/api/investigate`
can pull a self-consistent, multi-stage "attack story" for demonstration
purposes (initial access -> execution -> credential access -> lateral
movement -> exfiltration).
"""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

_NOW = datetime.now(timezone.utc)


def _ts(minutes_ago: int) -> str:
    return (_NOW - timedelta(minutes=minutes_ago)).isoformat()


# ---------------------------------------------------------------------------
# Windows Security Event Log fixtures
# ---------------------------------------------------------------------------
WINDOWS_EVENT_LOGS: List[Dict[str, Any]] = [
    {
        "evidence_id": "win-4624-001",
        "source": "windows_event_log",
        "event_id": 4624,
        "description": "An account was successfully logged on",
        "host": "WKSTN-FIN-07",
        "user": "svc_backup",
        "logon_type": 3,
        "src_ip": "10.12.4.55",
        "timestamp": _ts(180),
    },
    {
        "evidence_id": "win-4688-002",
        "source": "windows_event_log",
        "event_id": 4688,
        "description": "A new process has been created",
        "host": "WKSTN-FIN-07",
        "user": "svc_backup",
        "process": "powershell.exe",
        "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        "parent_process": "winword.exe",
        "timestamp": _ts(175),
    },
    {
        "evidence_id": "win-4672-003",
        "source": "windows_event_log",
        "event_id": 4672,
        "description": "Special privileges assigned to new logon",
        "host": "WKSTN-FIN-07",
        "user": "svc_backup",
        "privileges": ["SeDebugPrivilege", "SeBackupPrivilege"],
        "timestamp": _ts(170),
    },
    {
        "evidence_id": "win-4624-004",
        "source": "windows_event_log",
        "event_id": 4624,
        "description": "An account was successfully logged on",
        "host": "SRV-DC-01",
        "user": "svc_backup",
        "logon_type": 3,
        "src_ip": "10.12.4.55",
        "timestamp": _ts(140),
    },
]

# ---------------------------------------------------------------------------
# Sysmon fixtures
# ---------------------------------------------------------------------------
SYSMON_EVENTS: List[Dict[str, Any]] = [
    {
        "evidence_id": "sysmon-1-001",
        "source": "sysmon",
        "event_id": 1,
        "description": "Process creation",
        "host": "WKSTN-FIN-07",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        "user": "FIN\\jsmith",
        "hashes": "SHA256=6C1B... (truncated)",
        "timestamp": _ts(176),
    },
    {
        "evidence_id": "sysmon-3-002",
        "source": "sysmon",
        "event_id": 3,
        "description": "Network connection",
        "host": "WKSTN-FIN-07",
        "image": "powershell.exe",
        "dest_ip": "185.220.101.47",
        "dest_port": 443,
        "protocol": "tcp",
        "timestamp": _ts(174),
    },
    {
        "evidence_id": "sysmon-11-003",
        "source": "sysmon",
        "event_id": 11,
        "description": "File create",
        "host": "WKSTN-FIN-07",
        "image": "powershell.exe",
        "target_filename": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\update.ps1",
        "timestamp": _ts(173),
    },
    {
        "evidence_id": "sysmon-1-004",
        "source": "sysmon",
        "event_id": 1,
        "description": "Process creation",
        "host": "WKSTN-FIN-07",
        "image": "C:\\Windows\\System32\\rundll32.exe",
        "parent_image": "powershell.exe",
        "command_line": "rundll32.exe comsvcs.dll, MiniDump 812 lsass.dmp full",
        "user": "FIN\\jsmith",
        "timestamp": _ts(165),
    },
    {
        "evidence_id": "sysmon-3-005",
        "source": "sysmon",
        "event_id": 3,
        "description": "Network connection",
        "host": "WKSTN-FIN-07",
        "image": "rundll32.exe",
        "dest_ip": "10.12.4.10",
        "dest_port": 445,
        "protocol": "tcp",
        "timestamp": _ts(150),
    },
    {
        "evidence_id": "sysmon-1-006",
        "source": "sysmon",
        "event_id": 1,
        "description": "Process creation",
        "host": "SRV-DC-01",
        "image": "C:\\Windows\\System32\\cmd.exe",
        "parent_image": "svchost.exe",
        "command_line": "cmd.exe /c whoami /all",
        "user": "FIN\\svc_backup",
        "timestamp": _ts(138),
    },
]

# ---------------------------------------------------------------------------
# Suricata EVE JSON fixtures
# ---------------------------------------------------------------------------
SURICATA_ALERTS: List[Dict[str, Any]] = [
    {
        "evidence_id": "suri-alert-001",
        "source": "suricata",
        "event_type": "alert",
        "signature": "ET MALWARE Cobalt Strike Beacon Observed (TLS SNI)",
        "signature_id": 2024297,
        "severity": 1,
        "src_ip": "10.12.4.55",
        "dest_ip": "185.220.101.47",
        "dest_port": 443,
        "proto": "TCP",
        "timestamp": _ts(174),
    },
    {
        "evidence_id": "suri-alert-002",
        "source": "suricata",
        "event_type": "alert",
        "signature": "ET POLICY SMB2 NT Create AndX Request For an Executable File",
        "signature_id": 2018959,
        "severity": 2,
        "src_ip": "10.12.4.55",
        "dest_ip": "10.12.4.10",
        "dest_port": 445,
        "proto": "TCP",
        "timestamp": _ts(150),
    },
    {
        "evidence_id": "suri-alert-003",
        "source": "suricata",
        "event_type": "alert",
        "signature": "ET HUNTING Possible LSASS Process Dump via comsvcs.dll",
        "signature_id": 2032234,
        "severity": 1,
        "src_ip": "10.12.4.55",
        "dest_ip": "10.12.4.55",
        "dest_port": 0,
        "proto": "N/A",
        "timestamp": _ts(165),
    },
    {
        "evidence_id": "suri-alert-004",
        "source": "suricata",
        "event_type": "alert",
        "signature": "ET EXFIL Large Outbound Data Transfer to Rare Destination",
        "signature_id": 2041123,
        "severity": 2,
        "src_ip": "10.12.4.10",
        "dest_ip": "185.220.101.47",
        "dest_port": 8443,
        "proto": "TCP",
        "timestamp": _ts(120),
    },
]

# ---------------------------------------------------------------------------
# Incident bundles: map a triggering incident_id to the evidence pool that
# the Investigation Agent is allowed to pull from during graph expansion.
# ---------------------------------------------------------------------------
INCIDENTS: Dict[str, Dict[str, Any]] = {
    "INC-2026-0railtrail": {  # kept for readability; canonical id below
        "title": "placeholder",
    },
}

INCIDENTS = {
    "INC-1001": {
        "incident_id": "INC-1001",
        "title": "Suspicious PowerShell -> LSASS Access -> Lateral Movement",
        "initial_alert": "suri-alert-001",
        "entry_host": "WKSTN-FIN-07",
        "entry_user": "FIN\\jsmith",
        "description": (
            "Endpoint WKSTN-FIN-07 spawned an encoded PowerShell process from "
            "Microsoft Word, beaconed to a known Cobalt Strike infrastructure "
            "IP, dumped LSASS memory via comsvcs.dll, then used harvested "
            "service-account credentials to authenticate to SRV-DC-01."
        ),
        "evidence_pool": (
            [e["evidence_id"] for e in WINDOWS_EVENT_LOGS]
            + [e["evidence_id"] for e in SYSMON_EVENTS]
            + [e["evidence_id"] for e in SURICATA_ALERTS]
        ),
    }
}


def get_all_evidence_by_id() -> Dict[str, Dict[str, Any]]:
    """Flatten all telemetry fixtures into a single lookup keyed by evidence_id."""
    all_items: List[Dict[str, Any]] = WINDOWS_EVENT_LOGS + SYSMON_EVENTS + SURICATA_ALERTS
    return {item["evidence_id"]: item for item in all_items}


def get_incident(incident_id: str) -> Dict[str, Any] | None:
    return INCIDENTS.get(incident_id)


def list_incidents() -> List[Dict[str, Any]]:
    return list(INCIDENTS.values())
