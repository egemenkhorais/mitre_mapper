from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock


HOST_STATE = defaultdict(
    lambda: {
        "flows": 0,
        "dns_queries": 0,
        "ldap_queries": 0,
        "smb_connections": 0,
        "rdp_connections": 0,
        "targets": set(),
        "ports": set(),
        "last_seen": None,
        "recent_flows": deque(maxlen=10_000),
    }
)

HOST_STATE_LOCK = Lock()


def utc_now():
    return datetime.now(timezone.utc)


def normalize_port(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def update_host_state(flow):
    """
    Beklenen flow örneği:

    {
        "src_ip": "10.10.10.10",
        "dst_ip": "10.10.10.20",
        "src_port": 51000,
        "dst_port": 445,
        "protocol": 6,
        "timestamp": 1234567890.0
    }
    """

    src = str(flow.get("src_ip", ""))
    dst = str(flow.get("dst_ip", ""))

    if not src or not dst:
        return

    src_port = normalize_port(flow.get("src_port", 0))
    dst_port = normalize_port(flow.get("dst_port", 0))
    protocol = normalize_port(flow.get("protocol", 0))

    event = {
        "src_ip": src,
        "dst_ip": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "timestamp": flow.get("timestamp"),
    }

    with HOST_STATE_LOCK:
        state = HOST_STATE[src]

        state["flows"] += 1
        state["targets"].add(dst)
        state["ports"].add(dst_port)
        state["recent_flows"].append(event)

        if dst_port == 53:
            state["dns_queries"] += 1

        elif dst_port in (389, 636):
            state["ldap_queries"] += 1

        elif dst_port == 445:
            state["smb_connections"] += 1

        elif dst_port == 3389:
            state["rdp_connections"] += 1

        state["last_seen"] = utc_now()


def detect_behaviors(src_ip):
    with HOST_STATE_LOCK:
        if src_ip not in HOST_STATE:
            return []

        state = HOST_STATE[src_ip]

        snapshot = {
            "flows": state["flows"],
            "dns_queries": state["dns_queries"],
            "ldap_queries": state["ldap_queries"],
            "smb_connections": state["smb_connections"],
            "rdp_connections": state["rdp_connections"],
            "unique_targets": len(state["targets"]),
            "unique_ports": len(state["ports"]),
            "last_seen": state["last_seen"],
        }

    findings = []

    if snapshot["unique_targets"] > 100:
        findings.append(
            {
                "behavior": "internal_network_scan",
                "mitre": "T1018",
                "score": 30,
                "evidence": {
                    "unique_targets": snapshot["unique_targets"],
                    "unique_ports": snapshot["unique_ports"],
                    "total_flows": snapshot["flows"],
                },
            }
        )

    if snapshot["ldap_queries"] > 50:
        findings.append(
            {
                "behavior": "ldap_enumeration",
                "mitre": "T1087",
                "score": 30,
                "evidence": {
                    "ldap_queries": snapshot["ldap_queries"],
                    "unique_targets": snapshot["unique_targets"],
                },
            }
        )

    if snapshot["dns_queries"] > 500:
        findings.append(
            {
                "behavior": "dns_anomaly",
                "mitre": "T1071.004",
                "score": 20,
                "evidence": {
                    "dns_queries": snapshot["dns_queries"],
                    "total_flows": snapshot["flows"],
                },
            }
        )

    if snapshot["smb_connections"] > 100:
        findings.append(
            {
                "behavior": "possible_lateral_movement",
                "mitre": "T1021.002",
                "score": 25,
                "evidence": {
                    "smb_connections": snapshot["smb_connections"],
                    "unique_targets": snapshot["unique_targets"],
                },
            }
        )

    if snapshot["rdp_connections"] > 50:
        findings.append(
            {
                "behavior": "rdp_spread",
                "mitre": "T1021.001",
                "score": 25,
                "evidence": {
                    "rdp_connections": snapshot["rdp_connections"],
                    "unique_targets": snapshot["unique_targets"],
                },
            }
        )

    return findings


def get_host_state(src_ip):
    with HOST_STATE_LOCK:
        if src_ip not in HOST_STATE:
            return None

        state = HOST_STATE[src_ip]

        return {
            "flows": state["flows"],
            "dns_queries": state["dns_queries"],
            "ldap_queries": state["ldap_queries"],
            "smb_connections": state["smb_connections"],
            "rdp_connections": state["rdp_connections"],
            "unique_targets": len(state["targets"]),
            "unique_ports": len(state["ports"]),
            "targets": sorted(state["targets"]),
            "ports": sorted(state["ports"]),
            "last_seen": (
                state["last_seen"].isoformat()
                if state["last_seen"] is not None
                else None
            ),
        }


def reset_host_state():
    with HOST_STATE_LOCK:
        HOST_STATE.clear()