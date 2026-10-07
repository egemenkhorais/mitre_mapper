from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
import time


# ==========================================================
# CONFIG
# ==========================================================

BEHAVIOR_WINDOW_SECONDS = 300
MAX_RECENT_FLOWS = 10_000


# ==========================================================
# HOST STATE
# ==========================================================

HOST_STATE = defaultdict(
    lambda: {
        "recent_flows": deque(
            maxlen=MAX_RECENT_FLOWS
        ),
        "last_seen": None,
    }
)

HOST_STATE_LOCK = Lock()


# ==========================================================
# HELPERS
# ==========================================================

def utc_now():
    return datetime.now(timezone.utc)


def normalize_port(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def normalize_timestamp(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return time.time()


def remove_expired_flows(
    recent_flows,
    current_time
):
    cutoff = (
        current_time
        - BEHAVIOR_WINDOW_SECONDS
    )

    while recent_flows:

        oldest_timestamp = (
            recent_flows[0]
            .get(
                "timestamp",
                0
            )
        )

        if oldest_timestamp >= cutoff:
            break

        recent_flows.popleft()


def build_snapshot(recent_flows):
    targets = set()
    ports = set()

    dns_queries = 0
    ldap_queries = 0
    smb_connections = 0
    rdp_connections = 0

    tcp_flows = 0
    udp_flows = 0

    for flow in recent_flows:

        dst_ip = flow.get(
            "dst_ip"
        )

        dst_port = normalize_port(
            flow.get(
                "dst_port",
                0
            )
        )

        protocol = normalize_port(
            flow.get(
                "protocol",
                0
            )
        )

        if dst_ip:
            targets.add(
                dst_ip
            )

        if dst_port:
            ports.add(
                dst_port
            )

        if protocol == 6:
            tcp_flows += 1

        elif protocol == 17:
            udp_flows += 1

        if dst_port == 53:
            dns_queries += 1

        elif dst_port in (
            389,
            636
        ):
            ldap_queries += 1

        elif dst_port == 445:
            smb_connections += 1

        elif dst_port == 3389:
            rdp_connections += 1

    return {
        "window_seconds":
            BEHAVIOR_WINDOW_SECONDS,

        "flows":
            len(recent_flows),

        "dns_queries":
            dns_queries,

        "ldap_queries":
            ldap_queries,

        "smb_connections":
            smb_connections,

        "rdp_connections":
            rdp_connections,

        "tcp_flows":
            tcp_flows,

        "udp_flows":
            udp_flows,

        "unique_targets":
            len(targets),

        "unique_ports":
            len(ports),

        "targets":
            sorted(targets),

        "ports":
            sorted(ports),
    }


# ==========================================================
# UPDATE HOST STATE
# ==========================================================

def update_host_state(flow):
    src = str(
        flow.get(
            "src_ip",
            ""
        )
    ).strip()

    dst = str(
        flow.get(
            "dst_ip",
            ""
        )
    ).strip()

    if not src or not dst:
        return

    event = {
        "src_ip":
            src,

        "dst_ip":
            dst,

        "src_port":
            normalize_port(
                flow.get(
                    "src_port",
                    0
                )
            ),

        "dst_port":
            normalize_port(
                flow.get(
                    "dst_port",
                    0
                )
            ),

        "protocol":
            normalize_port(
                flow.get(
                    "protocol",
                    0
                )
            ),

        "timestamp":
            normalize_timestamp(
                flow.get(
                    "timestamp"
                )
            ),
    }

    current_time = time.time()

    with HOST_STATE_LOCK:

        state = HOST_STATE[src]

        remove_expired_flows(
            state["recent_flows"],
            current_time
        )

        state[
            "recent_flows"
        ].append(
            event
        )

        state[
            "last_seen"
        ] = utc_now()


# ==========================================================
# DETECT BEHAVIORS
# ==========================================================

def detect_behaviors(src_ip):
    src_ip = str(
        src_ip
    ).strip()

    current_time = time.time()

    with HOST_STATE_LOCK:

        if src_ip not in HOST_STATE:
            return []

        state = HOST_STATE[
            src_ip
        ]

        remove_expired_flows(
            state["recent_flows"],
            current_time
        )

        snapshot = build_snapshot(
            list(
                state[
                    "recent_flows"
                ]
            )
        )

    findings = []

    # ------------------------------------------------------
    # INTERNAL NETWORK SCAN
    # ------------------------------------------------------

    if (
        snapshot[
            "unique_targets"
        ] > 100
    ):
        findings.append(
            {
                "behavior":
                    "internal_network_scan",

                "score":
                    30,

                "confidence":
                    min(
                        snapshot[
                            "unique_targets"
                        ] / 200,
                        1.0
                    ),

                "evidence": {
                    "window_seconds":
                        snapshot[
                            "window_seconds"
                        ],

                    "unique_targets":
                        snapshot[
                            "unique_targets"
                        ],

                    "unique_ports":
                        snapshot[
                            "unique_ports"
                        ],

                    "total_flows":
                        snapshot[
                            "flows"
                        ],

                    "ports":
                        snapshot[
                            "ports"
                        ],
                },
            }
        )

    # ------------------------------------------------------
    # LDAP ENUMERATION
    # ------------------------------------------------------

    if (
        snapshot[
            "ldap_queries"
        ] > 50
    ):
        findings.append(
            {
                "behavior":
                    "ldap_enumeration",

                "score":
                    30,

                "confidence":
                    min(
                        snapshot[
                            "ldap_queries"
                        ] / 100,
                        1.0
                    ),

                "evidence": {
                    "window_seconds":
                        snapshot[
                            "window_seconds"
                        ],

                    "ldap_queries":
                        snapshot[
                            "ldap_queries"
                        ],

                    "unique_targets":
                        snapshot[
                            "unique_targets"
                        ],

                    "ports": [
                        port
                        for port in (
                            389,
                            636
                        )
                        if port in snapshot[
                            "ports"
                        ]
                    ],
                },
            }
        )

    # ------------------------------------------------------
    # DNS ANOMALY
    # ------------------------------------------------------

    if (
        snapshot[
            "dns_queries"
        ] > 500
    ):
        findings.append(
            {
                "behavior":
                    "dns_anomaly",

                "score":
                    20,

                "confidence":
                    min(
                        snapshot[
                            "dns_queries"
                        ] / 1000,
                        1.0
                    ),

                "evidence": {
                    "window_seconds":
                        snapshot[
                            "window_seconds"
                        ],

                    "dns_queries":
                        snapshot[
                            "dns_queries"
                        ],

                    "total_flows":
                        snapshot[
                            "flows"
                        ],

                    "unique_targets":
                        snapshot[
                            "unique_targets"
                        ],
                },
            }
        )

    # ------------------------------------------------------
    # SMB LATERAL MOVEMENT
    # ------------------------------------------------------

    if (
        snapshot[
            "smb_connections"
        ] > 100
    ):
        findings.append(
            {
                "behavior":
                    "possible_lateral_movement",

                "score":
                    25,

                "confidence":
                    min(
                        snapshot[
                            "smb_connections"
                        ] / 200,
                        1.0
                    ),

                "evidence": {
                    "window_seconds":
                        snapshot[
                            "window_seconds"
                        ],

                    "smb_connections":
                        snapshot[
                            "smb_connections"
                        ],

                    "unique_targets":
                        snapshot[
                            "unique_targets"
                        ],

                    "destination_port":
                        445,
                },
            }
        )

    # ------------------------------------------------------
    # RDP SPREAD
    # ------------------------------------------------------

    if (
        snapshot[
            "rdp_connections"
        ] > 50
    ):
        findings.append(
            {
                "behavior":
                    "rdp_spread",

                "score":
                    25,

                "confidence":
                    min(
                        snapshot[
                            "rdp_connections"
                        ] / 100,
                        1.0
                    ),

                "evidence": {
                    "window_seconds":
                        snapshot[
                            "window_seconds"
                        ],

                    "rdp_connections":
                        snapshot[
                            "rdp_connections"
                        ],

                    "unique_targets":
                        snapshot[
                            "unique_targets"
                        ],

                    "destination_port":
                        3389,
                },
            }
        )

    return findings


# ==========================================================
# GET HOST STATE
# ==========================================================

def get_host_state(src_ip):
    src_ip = str(
        src_ip
    ).strip()

    current_time = time.time()

    with HOST_STATE_LOCK:

        if src_ip not in HOST_STATE:
            return None

        state = HOST_STATE[
            src_ip
        ]

        remove_expired_flows(
            state["recent_flows"],
            current_time
        )

        snapshot = build_snapshot(
            list(
                state[
                    "recent_flows"
                ]
            )
        )

        return {
            **snapshot,

            "last_seen": (
                state[
                    "last_seen"
                ].isoformat()
                if state[
                    "last_seen"
                ] is not None
                else None
            ),
        }


# ==========================================================
# RESET
# ==========================================================

def reset_host_state():
    with HOST_STATE_LOCK:
        HOST_STATE.clear()