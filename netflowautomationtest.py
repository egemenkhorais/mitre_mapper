# netflowautomationtest.py

import re
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS

warnings.filterwarnings("ignore")

FTP_REPLY_PATTERN = re.compile(rb"^(\d{3})[\s-]")


def get_transport_info(pkt):
    if TCP in pkt:
        return (int(pkt[TCP].sport), int(pkt[TCP].dport), 6)
    if UDP in pkt:
        return (int(pkt[UDP].sport), int(pkt[UDP].dport), 17)
    if ICMP in pkt:
        return 0, 0, 1
    if IP in pkt:
        return 0, 0, int(pkt[IP].proto)
    return 0, 0, 0


def make_forward_key(src, dst, sport, dport, proto):
    return (src, dst, int(sport), int(dport), int(proto))


def make_reverse_key(src, dst, sport, dport, proto):
    return (dst, src, int(dport), int(sport), int(proto))


def directional_duration_ms(first_ts, last_ts):
    if first_ts is None or last_ts is None:
        return 0.0
    return max(0.0, (float(last_ts) - float(first_ts)) * 1000.0)


def calculate_second_bytes(byte_count, first_ts, last_ts):
    if byte_count <= 0:
        return 0.0
    duration_ms = directional_duration_ms(first_ts, last_ts)
    effective_seconds = max(duration_ms / 1000.0, 0.001)
    return float(byte_count) / effective_seconds


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
    consumed_sequence = payload_length
    flags = int(tcp.flags)
    if flags & 0x02: consumed_sequence += 1  # SYN
    if flags & 0x01: consumed_sequence += 1  # FIN
    if consumed_sequence <= 0:
        return None
    start = int(tcp.seq)
    end = start + consumed_sequence
    return start, end, payload_length


def ranges_overlap(start_a, end_a, start_b, end_b):
    return start_a < end_b and start_b < end_a


def first_dns_answer_ttl(dns):
    if int(dns.ancount or 0) <= 0:
        return 0
    ttls = []
    current = dns.an
    for _ in range(int(dns.ancount or 0)):
        if current is None: break
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
    if DNS in pkt: return 1
    if source_port == 21 or destination_port == 21: return 2
    if source_port in {443, 8443} or destination_port in {443, 8443}: return 3
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
        "first_in_ts": None,
        "last_in_ts": None,
        "first_out_ts": None,
        "last_out_ts": None,
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
        "L7_PROTO": 0
    }


def update_directional_statistics(flow, pkt, direction):
    timestamp = float(pkt.time)
    ip_packet_length = int(pkt[IP].len or len(pkt[IP]))
    flow["last_ts"] = max(flow["last_ts"], timestamp)
    if direction == "in":
        flow["IN_BYTES"] += ip_packet_length
        flow["IN_PKTS"] += 1
        if flow["first_in_ts"] is None: flow["first_in_ts"] = timestamp
        flow["last_in_ts"] = timestamp
    else:
        flow["OUT_BYTES"] += ip_packet_length
        flow["OUT_PKTS"] += 1
        if flow["first_out_ts"] is None: flow["first_out_ts"] = timestamp
        flow["last_out_ts"] = timestamp


def update_length_statistics(flow, pkt):
    frame_length = len(pkt)
    ip_packet_length = int(pkt[IP].len or len(pkt[IP]))
    flow["LONGEST_FLOW_PKT"] = max(flow["LONGEST_FLOW_PKT"], frame_length)
    if flow["SHORTEST_FLOW_PKT"] is None:
        flow["SHORTEST_FLOW_PKT"] = frame_length
    else:
        flow["SHORTEST_FLOW_PKT"] = min(flow["SHORTEST_FLOW_PKT"], frame_length)

    flow["MAX_IP_PKT_LEN"] = max(flow["MAX_IP_PKT_LEN"], ip_packet_length)
    if flow["MIN_IP_PKT_LEN"] is None:
        flow["MIN_IP_PKT_LEN"] = ip_packet_length
    else:
        flow["MIN_IP_PKT_LEN"] = min(flow["MIN_IP_PKT_LEN"], ip_packet_length)

    ttl = int(pkt[IP].ttl)
    if flow["MIN_TTL"] is None:
        flow["MIN_TTL"] = ttl
    else:
        flow["MIN_TTL"] = min(flow["MIN_TTL"], ttl)
    flow["MAX_TTL"] = max(flow["MAX_TTL"], ttl)
    update_packet_size_bin(flow, frame_length)


def update_tcp_statistics(flow, pkt, direction):
    if TCP not in pkt: return
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
    sequence_info = tcp_sequence_range(pkt)
    if sequence_info is None: return
    start, end, payload_length = sequence_info
    ranges_key = "seen_tcp_ranges_in" if direction == "in" else "seen_tcp_ranges_out"
    is_retransmission = any(ranges_overlap(start, end, old_start, old_end) for old_start, old_end in flow[ranges_key])

    if is_retransmission:
        if direction == "in":
            flow["RETRANSMITTED_IN_PKTS"] += 1
            flow["RETRANSMITTED_IN_BYTES"] += payload_length
        else:
            flow["RETRANSMITTED_OUT_PKTS"] += 1
            flow["RETRANSMITTED_OUT_BYTES"] += payload_length
    else:
        flow[ranges_key].append((start, end))


def update_dns_statistics(flow, pkt):
    if DNS not in pkt: return
    dns = pkt[DNS]
    flow["L7_PROTO"] = 1
    flow["DNS_QUERY_ID"] = int(dns.id or 0)
    if dns.qd is not None:
        try:
            question = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
            flow["DNS_QUERY_TYPE"] = int(question.qtype or 0)
        except (AttributeError, TypeError, ValueError, IndexError):
            pass
    if int(dns.qr or 0) == 1:
        answer_ttl = first_dns_answer_ttl(dns)
        if answer_ttl > 0: flow["DNS_TTL_ANSWER"] = answer_ttl


def update_icmp_statistics(flow, pkt):
    if ICMP not in pkt: return
    icmp_type = int(pkt[ICMP].type or 0)
    flow["ICMP_TYPE"] = icmp_type
    flow["ICMP_IPV4_TYPE"] = icmp_type


def update_ftp_statistics(flow, pkt):
    if TCP not in pkt or Raw not in pkt: return
    source_port = int(pkt[TCP].sport)
    destination_port = int(pkt[TCP].dport)
    if source_port != 21 and destination_port != 21: return
    flow["L7_PROTO"] = 2
    payload = bytes(pkt[Raw].load)
    match = FTP_REPLY_PATTERN.match(payload)
    if match: flow["FTP_COMMAND_RET_CODE"] = int(match.group(1))


def finalize_flow(flow):
    flow_duration_ms = max(0.0, (flow["last_ts"] - flow["first_ts"]) * 1000.0)
    duration_in_ms = directional_duration_ms(flow["first_in_ts"], flow["last_in_ts"])
    duration_out_ms = directional_duration_ms(flow["first_out_ts"], flow["last_out_ts"])
    src_second_bytes = calculate_second_bytes(flow["IN_BYTES"], flow["first_in_ts"], flow["last_in_ts"])
    dst_second_bytes = calculate_second_bytes(flow["OUT_BYTES"], flow["first_out_ts"], flow["last_out_ts"])

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
        "SHORTEST_FLOW_PKT": flow["SHORTEST_FLOW_PKT"] if flow["SHORTEST_FLOW_PKT"] is not None else 0,
        "MIN_IP_PKT_LEN": flow["MIN_IP_PKT_LEN"] if flow["MIN_IP_PKT_LEN"] is not None else 0,
        "MAX_IP_PKT_LEN": flow["MAX_IP_PKT_LEN"],
        "SRC_TO_DST_SECOND_BYTES": src_second_bytes,
        "DST_TO_SRC_SECOND_BYTES": dst_second_bytes,
        "RETRANSMITTED_IN_BYTES": flow["RETRANSMITTED_IN_BYTES"],
        "RETRANSMITTED_IN_PKTS": flow["RETRANSMITTED_IN_PKTS"],
        "RETRANSMITTED_OUT_BYTES": flow["RETRANSMITTED_OUT_BYTES"],
        "RETRANSMITTED_OUT_PKTS": flow["RETRANSMITTED_OUT_PKTS"],
        "SRC_TO_DST_AVG_THROUGHPUT": src_second_bytes * 8.0,
        "DST_TO_SRC_AVG_THROUGHPUT": dst_second_bytes * 8.0,
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
        "FTP_COMMAND_RET_CODE": flow["FTP_COMMAND_RET_CODE"]
    }


# ==========================================================
# ANA FONKSIYON: live_soc.py TARAFINDAN ÇAĞRILACAK KISIM
# ==========================================================

def extract_features_from_pcap(pcap_path):
    """
    Belirtilen PCAP dosyasını okur, paketleri flowlara gruplar ve her flow'un
    özniteliklerini XGBoost modeline girecek formata dönüştürür.

    Dönüş:
    (features_df, flow_packets)
    - features_df: Model tahminine uygun DataFrame
    - flow_packets: Dictionary. Key: (src, dst, sport, dport, proto), Value: [paket, paket, ...]
    """
    packets = rdpcap(str(pcap_path))
    flows = {}

    # live_soc.py ham PCAP çıkarmak istediği için paketleri flowlara göre saklıyoruz.
    flow_packets = {}

    for pkt in packets:
        if IP not in pkt: continue

        source_ip = pkt[IP].src
        destination_ip = pkt[IP].dst
        source_port, destination_port, protocol = get_transport_info(pkt)

        forward_key = make_forward_key(source_ip, destination_ip, source_port, destination_port, protocol)
        reverse_key = make_reverse_key(source_ip, destination_ip, source_port, destination_port, protocol)

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
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
                timestamp=float(pkt.time)
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
        if flow["L7_PROTO"] == 0:
            flow["L7_PROTO"] = detected_l7

    feature_rows = [finalize_flow(flow) for flow in flows.values()]

    if not feature_rows:
        return pd.DataFrame(), {}

    features = pd.DataFrame(feature_rows)

    try:
        # artifacts klasörü ana dizinde varsayılıyor (live_soc.py ile aynı yerde)
        feature_names = joblib.load(Path("artifacts/feature_names.joblib"))

        # Olası eksik feature'ları tamamla
        for col in feature_names:
            if col not in features.columns:
                features[col] = 0.0

        # Sütunları modelin eğitildiği sıra ile aynı hale getir
        features = features[feature_names].copy()
    except Exception as e:
        print(f"Warning: feature_names.joblib failed to load: {e}")

    # XGBoost için güvenli format (NaN, Inf temizliği)
    features = features.apply(pd.to_numeric, errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan)
    features = features.fillna(0.0)

    FLOAT32_SAFE_LIMIT = np.finfo(np.float32).max / 10.0
    features = features.clip(lower=-FLOAT32_SAFE_LIMIT, upper=FLOAT32_SAFE_LIMIT)
    features = features.astype(np.float32)

    return features, flow_packets