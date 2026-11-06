# netflowautomationtest.py

import re
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS

warnings.filterwarnings("ignore")

FTP_REPLY_PATTERN = re.compile(rb"^(\d{3})[\s-]")
BASE_DIR = Path(__file__).resolve().parent
FEATURE_NAMES_PATH = BASE_DIR / "artifacts" / "feature_names.joblib"

# IMPORTANT:
# NF-UQ-NIDS/NFStream L7_PROTO is not a custom DNS=1, FTP=2, HTTPS=3 field.
# Arbitrary values create severe live/training feature drift. Until the exact
# training-time application-protocol encoder is available, keep it unknown (0).
USE_CUSTOM_L7_MAPPING = False

# Very short one-packet flows otherwise produce artificial multi-MB/s rates.
# This does not invent duration. A zero-duration direction gets rate 0.
ZERO_DURATION_RATE = 0.0


def get_transport_info(pkt):
    if TCP in pkt:
        return int(pkt[TCP].sport), int(pkt[TCP].dport), 6
    if UDP in pkt:
        return int(pkt[UDP].sport), int(pkt[UDP].dport), 17
    if ICMP in pkt:
        return 0, 0, 1
    if IP in pkt:
        return 0, 0, int(pkt[IP].proto)
    return 0, 0, 0


def make_forward_key(src, dst, sport, dport, proto):
    return src, dst, int(sport), int(dport), int(proto)


def make_reverse_key(src, dst, sport, dport, proto):
    return dst, src, int(dport), int(sport), int(proto)


def directional_duration_ms(first_ts, last_ts):
    if first_ts is None or last_ts is None:
        return 0.0
    return max(0.0, (float(last_ts) - float(first_ts)) * 1000.0)


def calculate_second_bytes(byte_count, first_ts, last_ts):
    if byte_count <= 0:
        return 0.0
    duration_ms = directional_duration_ms(first_ts, last_ts)
    if duration_ms <= 0.0:
        return ZERO_DURATION_RATE
    return float(byte_count) / (duration_ms / 1000.0)


def update_packet_size_bin(flow, packet_size):
    if packet_size <= 128:
        flow["NUM_PKTS_UP_TO_128_BYTES"] += 1
    elif packet_size <= 256:
        flow["NUM_PKTS_128_TO_256_BYTES"] += 1
    elif packet_size <= 512:
        flow["NUM_PKTS_256_TO_512_BYTES"] += 1
    elif packet_size <= 1024:
        flow["NUM_PKTS_512_TO_1024_BYTES"] += 1
    elif packet_size <= 1514:
        flow["NUM_PKTS_1024_TO_1514_BYTES"] += 1


def tcp_sequence_range(pkt):
    if TCP not in pkt:
        return None
    tcp = pkt[TCP]
    payload_length = len(bytes(tcp.payload))
    consumed = payload_length
    flags = int(tcp.flags)
    if flags & 0x02:
        consumed += 1
    if flags & 0x01:
        consumed += 1
    if consumed <= 0:
        return None
    start = int(tcp.seq)
    return start, start + consumed, payload_length


def ranges_overlap(start_a, end_a, start_b, end_b):
    return start_a < end_b and start_b < end_a


def first_dns_answer_ttl(dns):
    if int(dns.ancount or 0) <= 0:
        return 0
    ttls = []
    current = dns.an
    for _ in range(int(dns.ancount or 0)):
        if current is None:
            break
        try:
            if hasattr(current, "ttl"):
                ttls.append(int(current.ttl))
        except (TypeError, ValueError):
            pass
        try:
            current = current.payload
        except AttributeError:
            break
    return min(ttls) if ttls else 0


def detect_l7_protocol(pkt, source_port, destination_port):
    if not USE_CUSTOM_L7_MAPPING:
        return 0
    if DNS in pkt:
        return 1
    if source_port == 21 or destination_port == 21:
        return 2
    if source_port in {443, 8443} or destination_port in {443, 8443}:
        return 3
    return 0


def create_flow(source_ip, destination_ip, source_port, destination_port, protocol, timestamp):
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": int(source_port),
        "destination_port": int(destination_port),
        "protocol": int(protocol),
        "first_ts": float(timestamp),
        "last_ts": float(timestamp),
        "first_src_to_dst_ts": None,
        "last_src_to_dst_ts": None,
        "first_dst_to_src_ts": None,
        "last_dst_to_src_ts": None,
        "IN_BYTES": 0,
        "IN_PKTS": 0,
        "OUT_BYTES": 0,
        "OUT_PKTS": 0,
        "TCP_FLAGS": 0,
        "CLIENT_TCP_FLAGS": 0,
        "SERVER_TCP_FLAGS": 0,
        "MIN_TTL": None,
        "MAX_TTL": 0,
        "LONGEST_FLOW_PKT": 0,
        "SHORTEST_FLOW_PKT": None,
        "MIN_IP_PKT_LEN": None,
        "MAX_IP_PKT_LEN": 0,
        "NUM_PKTS_UP_TO_128_BYTES": 0,
        "NUM_PKTS_128_TO_256_BYTES": 0,
        "NUM_PKTS_256_TO_512_BYTES": 0,
        "NUM_PKTS_512_TO_1024_BYTES": 0,
        "NUM_PKTS_1024_TO_1514_BYTES": 0,
        "TCP_WIN_MAX_IN": 0,
        "TCP_WIN_MAX_OUT": 0,
        "RETRANSMITTED_IN_BYTES": 0,
        "RETRANSMITTED_IN_PKTS": 0,
        "RETRANSMITTED_OUT_BYTES": 0,
        "RETRANSMITTED_OUT_PKTS": 0,
        "seen_tcp_ranges_in": [],
        "seen_tcp_ranges_out": [],
        "ICMP_TYPE": 0,
        "ICMP_IPV4_TYPE": 0,
        "DNS_QUERY_ID": 0,
        "DNS_QUERY_TYPE": 0,
        "DNS_TTL_ANSWER": 0,
        "FTP_COMMAND_RET_CODE": 0,
        "L7_PROTO": 0,
    }


def update_directional_statistics(flow, pkt, direction):
    timestamp = float(pkt.time)
    ip_length = int(pkt[IP].len or len(pkt[IP]))
    flow["last_ts"] = max(flow["last_ts"], timestamp)

    # IN = initiator/source -> responder/destination.
    # OUT = responder/destination -> initiator/source.
    if direction == "in":
        flow["IN_BYTES"] += ip_length
        flow["IN_PKTS"] += 1
        if flow["first_src_to_dst_ts"] is None:
            flow["first_src_to_dst_ts"] = timestamp
        flow["last_src_to_dst_ts"] = timestamp
    else:
        flow["OUT_BYTES"] += ip_length
        flow["OUT_PKTS"] += 1
        if flow["first_dst_to_src_ts"] is None:
            flow["first_dst_to_src_ts"] = timestamp
        flow["last_dst_to_src_ts"] = timestamp


def update_length_statistics(flow, pkt):
    # Training features are IP-length based. Using Ethernet frame length adds
    # link-layer bytes and causes environment-dependent drift.
    ip_length = int(pkt[IP].len or len(pkt[IP]))

    flow["LONGEST_FLOW_PKT"] = max(flow["LONGEST_FLOW_PKT"], ip_length)
    flow["SHORTEST_FLOW_PKT"] = (
        ip_length if flow["SHORTEST_FLOW_PKT"] is None
        else min(flow["SHORTEST_FLOW_PKT"], ip_length)
    )
    flow["MAX_IP_PKT_LEN"] = max(flow["MAX_IP_PKT_LEN"], ip_length)
    flow["MIN_IP_PKT_LEN"] = (
        ip_length if flow["MIN_IP_PKT_LEN"] is None
        else min(flow["MIN_IP_PKT_LEN"], ip_length)
    )

    ttl = int(pkt[IP].ttl or 0)
    flow["MIN_TTL"] = ttl if flow["MIN_TTL"] is None else min(flow["MIN_TTL"], ttl)
    flow["MAX_TTL"] = max(flow["MAX_TTL"], ttl)
    update_packet_size_bin(flow, ip_length)


def update_tcp_statistics(flow, pkt, direction):
    if TCP not in pkt:
        return
    flags = int(pkt[TCP].flags)
    window = int(pkt[TCP].window or 0)
    flow["TCP_FLAGS"] |= flags
    if direction == "in":
        flow["CLIENT_TCP_FLAGS"] |= flags
        flow["TCP_WIN_MAX_IN"] = max(flow["TCP_WIN_MAX_IN"], window)
    else:
        flow["SERVER_TCP_FLAGS"] |= flags
        flow["TCP_WIN_MAX_OUT"] = max(flow["TCP_WIN_MAX_OUT"], window)


def update_retransmission_statistics(flow, pkt, direction):
    info = tcp_sequence_range(pkt)
    if info is None:
        return
    start, end, payload_length = info
    ranges_key = "seen_tcp_ranges_in" if direction == "in" else "seen_tcp_ranges_out"
    retransmission = any(
        ranges_overlap(start, end, old_start, old_end)
        for old_start, old_end in flow[ranges_key]
    )

    if retransmission:
        if direction == "in":
            flow["RETRANSMITTED_IN_PKTS"] += 1
            flow["RETRANSMITTED_IN_BYTES"] += payload_length
        else:
            flow["RETRANSMITTED_OUT_PKTS"] += 1
            flow["RETRANSMITTED_OUT_BYTES"] += payload_length
    else:
        flow[ranges_key].append((start, end))


def update_dns_statistics(flow, pkt):
    if DNS not in pkt:
        return
    dns = pkt[DNS]
    # Do not set L7_PROTO to an arbitrary custom code.
    flow["DNS_QUERY_ID"] = int(dns.id or 0)
    if dns.qd is not None:
        try:
            question = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
            flow["DNS_QUERY_TYPE"] = int(question.qtype or 0)
        except (AttributeError, TypeError, ValueError, IndexError):
            pass
    if int(dns.qr or 0) == 1:
        answer_ttl = first_dns_answer_ttl(dns)
        if answer_ttl > 0:
            flow["DNS_TTL_ANSWER"] = answer_ttl


def update_icmp_statistics(flow, pkt):
    if ICMP not in pkt:
        return
    icmp_type = int(pkt[ICMP].type or 0)
    flow["ICMP_TYPE"] = icmp_type
    flow["ICMP_IPV4_TYPE"] = icmp_type


def update_ftp_statistics(flow, pkt):
    if TCP not in pkt or Raw not in pkt:
        return
    source_port = int(pkt[TCP].sport)
    destination_port = int(pkt[TCP].dport)
    if source_port != 21 and destination_port != 21:
        return
    payload = bytes(pkt[Raw].load)
    match = FTP_REPLY_PATTERN.match(payload)
    if match:
        flow["FTP_COMMAND_RET_CODE"] = int(match.group(1))


def finalize_flow(flow):
    flow_duration_ms = max(0.0, (flow["last_ts"] - flow["first_ts"]) * 1000.0)
    duration_in_ms = directional_duration_ms(
        flow["first_src_to_dst_ts"], flow["last_src_to_dst_ts"]
    )
    duration_out_ms = directional_duration_ms(
        flow["first_dst_to_src_ts"], flow["last_dst_to_src_ts"]
    )
    src_rate = calculate_second_bytes(
        flow["IN_BYTES"], flow["first_src_to_dst_ts"], flow["last_src_to_dst_ts"]
    )
    dst_rate = calculate_second_bytes(
        flow["OUT_BYTES"], flow["first_dst_to_src_ts"], flow["last_dst_to_src_ts"]
    )

    return {
        "PROTOCOL": flow["protocol"],
        "L7_PROTO": flow["L7_PROTO"],
        "IN_BYTES": flow["IN_BYTES"],
        "IN_PKTS": flow["IN_PKTS"],
        "OUT_BYTES": flow["OUT_BYTES"],
        "OUT_PKTS": flow["OUT_PKTS"],
        "TCP_FLAGS": flow["TCP_FLAGS"],
        "CLIENT_TCP_FLAGS": flow["CLIENT_TCP_FLAGS"],
        "SERVER_TCP_FLAGS": flow["SERVER_TCP_FLAGS"],
        "FLOW_DURATION_MILLISECONDS": flow_duration_ms,
        "DURATION_IN": duration_in_ms,
        "DURATION_OUT": duration_out_ms,
        "MIN_TTL": flow["MIN_TTL"] if flow["MIN_TTL"] is not None else 0,
        "MAX_TTL": flow["MAX_TTL"],
        "LONGEST_FLOW_PKT": flow["LONGEST_FLOW_PKT"],
        "SHORTEST_FLOW_PKT": flow["SHORTEST_FLOW_PKT"] or 0,
        "MIN_IP_PKT_LEN": flow["MIN_IP_PKT_LEN"] or 0,
        "MAX_IP_PKT_LEN": flow["MAX_IP_PKT_LEN"],
        "SRC_TO_DST_SECOND_BYTES": src_rate,
        "DST_TO_SRC_SECOND_BYTES": dst_rate,
        "RETRANSMITTED_IN_BYTES": flow["RETRANSMITTED_IN_BYTES"],
        "RETRANSMITTED_IN_PKTS": flow["RETRANSMITTED_IN_PKTS"],
        "RETRANSMITTED_OUT_BYTES": flow["RETRANSMITTED_OUT_BYTES"],
        "RETRANSMITTED_OUT_PKTS": flow["RETRANSMITTED_OUT_PKTS"],
        "SRC_TO_DST_AVG_THROUGHPUT": src_rate * 8.0,
        "DST_TO_SRC_AVG_THROUGHPUT": dst_rate * 8.0,
        "NUM_PKTS_UP_TO_128_BYTES": flow["NUM_PKTS_UP_TO_128_BYTES"],
        "NUM_PKTS_128_TO_256_BYTES": flow["NUM_PKTS_128_TO_256_BYTES"],
        "NUM_PKTS_256_TO_512_BYTES": flow["NUM_PKTS_256_TO_512_BYTES"],
        "NUM_PKTS_512_TO_1024_BYTES": flow["NUM_PKTS_512_TO_1024_BYTES"],
        "NUM_PKTS_1024_TO_1514_BYTES": flow["NUM_PKTS_1024_TO_1514_BYTES"],
        "TCP_WIN_MAX_IN": flow["TCP_WIN_MAX_IN"],
        "TCP_WIN_MAX_OUT": flow["TCP_WIN_MAX_OUT"],
        "ICMP_TYPE": flow["ICMP_TYPE"],
        "ICMP_IPV4_TYPE": flow["ICMP_IPV4_TYPE"],
        "DNS_QUERY_ID": flow["DNS_QUERY_ID"],
        "DNS_QUERY_TYPE": flow["DNS_QUERY_TYPE"],
        "DNS_TTL_ANSWER": flow["DNS_TTL_ANSWER"],
        "FTP_COMMAND_RET_CODE": flow["FTP_COMMAND_RET_CODE"],
    }


def validate_feature_schema(features, feature_names):
    feature_names = list(feature_names)
    duplicate_expected = pd.Index(feature_names)[pd.Index(feature_names).duplicated()].tolist()
    if duplicate_expected:
        raise ValueError(f"feature_names.joblib duplicate columns: {duplicate_expected}")

    missing = [name for name in feature_names if name not in features.columns]
    extras = [name for name in features.columns if name not in feature_names]

    if missing:
        print("FEATURE SCHEMA INFO -> missing columns filled with 0:", missing)
    if extras:
        print("FEATURE SCHEMA INFO -> unused extracted columns:", extras)

    for column in missing:
        features[column] = 0.0

    aligned = features.loc[:, feature_names].copy()
    if list(aligned.columns) != feature_names:
        raise RuntimeError("Feature column order could not be aligned.")
    return aligned


def extract_features_from_pcap(pcap_path):
    packets = rdpcap(str(pcap_path))
    flows = {}
    flow_packets = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        source_ip = str(pkt[IP].src)
        destination_ip = str(pkt[IP].dst)
        source_port, destination_port, protocol = get_transport_info(pkt)

        forward_key = make_forward_key(
            source_ip, destination_ip, source_port, destination_port, protocol
        )
        reverse_key = make_reverse_key(
            source_ip, destination_ip, source_port, destination_port, protocol
        )

        if forward_key in flows:
            flow_key = forward_key
            direction = "in"
        elif reverse_key in flows:
            flow_key = reverse_key
            direction = "out"
        else:
            flow_key = forward_key
            direction = "in"
            flows[flow_key] = create_flow(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                float(pkt.time),
            )
            flow_packets[flow_key] = []

        flow = flows[flow_key]
        flow_packets[flow_key].append(pkt)

        update_directional_statistics(flow, pkt, direction)
        update_length_statistics(flow, pkt)
        update_tcp_statistics(flow, pkt, direction)
        update_retransmission_statistics(flow, pkt, direction)
        update_dns_statistics(flow, pkt)
        update_icmp_statistics(flow, pkt)
        update_ftp_statistics(flow, pkt)

        detected_l7 = detect_l7_protocol(pkt, source_port, destination_port)
        if flow["L7_PROTO"] == 0 and detected_l7 != 0:
            flow["L7_PROTO"] = detected_l7

    if not flows:
        return pd.DataFrame(), {}

    # Dict insertion order keeps rows aligned with flow_packets keys.
    feature_rows = [finalize_flow(flow) for flow in flows.values()]
    features = pd.DataFrame(feature_rows)

    if not FEATURE_NAMES_PATH.exists():
        raise FileNotFoundError(
            f"Model feature artifact not found: {FEATURE_NAMES_PATH}"
        )

    feature_names = list(joblib.load(FEATURE_NAMES_PATH))
    features = validate_feature_schema(features, feature_names)

    features = features.apply(pd.to_numeric, errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    float32_limit = np.finfo(np.float32).max / 10.0
    features = features.clip(lower=-float32_limit, upper=float32_limit)
    features = features.astype(np.float32)

    # Runtime diagnostics: catches extractor/model drift immediately.
    if not np.isfinite(features.to_numpy()).all():
        raise ValueError("Non-finite values remained after feature sanitization.")

    print(
        "FEATURE CHECK ->",
        f"rows={len(features)}",
        f"columns={features.shape[1]}",
        f"expected={len(feature_names)}",
        f"order_match={list(features.columns) == feature_names}",
    )

    zero_duration_count = int((features.get("FLOW_DURATION_MILLISECONDS", 0) == 0).sum())
    short_flow_count = int(
        ((features.get("IN_PKTS", 0) + features.get("OUT_PKTS", 0)) <= 2).sum()
    )
    print(
        "FEATURE QUALITY ->",
        f"zero_duration={zero_duration_count}",
        f"flows_with_2_or_fewer_packets={short_flow_count}",
    )

    return features, flow_packets
