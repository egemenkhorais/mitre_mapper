# live_soc.py

from pathlib import Path
import time
import json
import tempfile

import numpy as np
import pandas as pd
import asyncio

try:
    asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

import pyshark
import joblib

from scapy.all import Ether
from scapy.utils import wrpcap

# ==========================================================
# IMPORT YOUR EXTRACTOR
# ==========================================================

from netflowautomationtest import extract_features_from_pcap

# ==========================================================
# CONFIG
# ==========================================================

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

INTERFACE = "4"

FLOW_TIMEOUT = 3

FLOW_BATCH_SIZE = 100

REVIEW_THRESHOLD = 0.50
ALERT_THRESHOLD = 0.80

MODEL_PATH = r"artifacts/xgb_nfv2_model.joblib"
ENCODER_PATH = r"artifacts/label_encoder.joblib"


from layer2_runtime import Layer2PayloadClassifier

layer2_classifier = Layer2PayloadClassifier(
    model_path="models/layer2_payload_classifier.joblib",
    confidence_threshold=0.80,
    max_payload_length=16384,
    decode_payload=True,
)

# Exact Layer 1 labels that should be routed to Layer 2.
# Add the exact web label from print(label_encoder.classes_) if needed.
LAYER2_WEB_LABELS = {
    "web attack",
    "web_attack",
    "webattack",
}

# ==========================================================
# OUTPUT
# ==========================================================

Path("alerts").mkdir(exist_ok=True)

# ==========================================================
# LOAD MODEL
# ==========================================================

model = joblib.load(MODEL_PATH)

label_encoder = joblib.load(
    ENCODER_PATH
)

# ==========================================================
# FLOW STORAGE
# ==========================================================

active_flows = {}

completed_flows = []

# ==========================================================
# FLOW KEY
# ==========================================================

def get_flow_key(packet):

    try:

        if not hasattr(packet, "ip"):
            return None

        proto = int(packet.ip.proto)

        if proto == 6:

            if not hasattr(packet, "tcp"):
                return None

            sport = int(
                packet.tcp.srcport
            )

            dport = int(
                packet.tcp.dstport
            )

        elif proto == 17:

            if not hasattr(packet, "udp"):
                return None

            sport = int(
                packet.udp.srcport
            )

            dport = int(
                packet.udp.dstport
            )

        else:
            return None

        return (
            packet.ip.src,
            packet.ip.dst,
            sport,
            dport,
            proto
        )

    except:
        return None

# ==========================================================
# DECISION
# ==========================================================

def decide(
    label,
    confidence
):

    if label == "Benign":
        return "BENIGN"

    if confidence < ALERT_THRESHOLD:
        return "REVIEW"

    return "ALERT"

# ==========================================================
# EXPORT FLOW
# ==========================================================

def export_flow_packets(
    packets,
    output_file
):

    scapy_packets = []

    for pkt in packets:

        try:

            raw = pkt.get_raw_packet()

            scapy_packets.append(
                Ether(
                    bytes(raw)
                )
            )

        except:
            pass

    if scapy_packets:

        wrpcap(
            output_file,
            scapy_packets
        )

# ==========================================================
# LAYER 2 - ADDITIVE HTTP PAYLOAD CLASSIFICATION
# ==========================================================

def should_run_layer2(label):

    normalized = str(label).strip().lower().replace("-", "_")

    return normalized in LAYER2_WEB_LABELS


def extract_http_request_from_pcap(pcap_file):
    """
    Best-effort extraction of unencrypted HTTP request evidence.

    Existing Layer 1 behavior is not changed. If no readable HTTP request
    exists, this function returns None and Layer 2 reports payload_unavailable.
    HTTPS payloads remain unavailable unless decrypted before this point.
    """

    http_capture = None

    try:

        http_capture = pyshark.FileCapture(
            str(pcap_file),
            tshark_path=TSHARK_PATH,
            display_filter="http.request",
            keep_packets=False,
            use_json=True
        )

        requests = []

        for packet in http_capture:

            if not hasattr(packet, "http"):
                continue

            http = packet.http

            method = getattr(
                http,
                "request_method",
                None
            )

            uri = getattr(
                http,
                "request_uri",
                None
            )

            full_uri = getattr(
                http,
                "request_full_uri",
                None
            )

            body = getattr(
                http,
                "file_data",
                None
            )

            if body is None:
                body = getattr(
                    http,
                    "request_body",
                    None
                )

            path = None
            query = None

            uri_text = str(
                full_uri or uri or ""
            )

            if uri_text:

                if "?" in uri_text:
                    path, query = uri_text.split(
                        "?",
                        1
                    )
                else:
                    path = uri_text

            headers = {}

            content_type = getattr(
                http,
                "content_type",
                None
            )

            user_agent = getattr(
                http,
                "user_agent",
                None
            )

            referer = getattr(
                http,
                "referer",
                None
            )

            if content_type:
                headers["content-type"] = str(content_type)

            if user_agent:
                headers["user-agent"] = str(user_agent)

            if referer:
                headers["referer"] = str(referer)

            if any([
                method,
                path,
                query,
                body
            ]):

                requests.append({
                    "method": str(method) if method else None,
                    "path": path,
                    "query": query,
                    "body": str(body) if body else None,
                    "headers": headers
                })

        if not requests:
            return None

        methods = [
            item["method"]
            for item in requests
            if item.get("method")
        ]

        paths = [
            item["path"]
            for item in requests
            if item.get("path")
        ]

        queries = [
            item["query"]
            for item in requests
            if item.get("query")
        ]

        bodies = [
            item["body"]
            for item in requests
            if item.get("body")
        ]

        headers = {}

        for item in requests:
            headers.update(
                item.get(
                    "headers",
                    {}
                )
            )

        return {
            "method": methods[0] if methods else None,
            "path": "\n".join(paths) if paths else None,
            "query": "\n".join(queries) if queries else None,
            "body": "\n".join(bodies) if bodies else None,
            "headers": headers,
            "request_count": len(requests)
        }

    except Exception as exc:

        print(
            f"LAYER2 HTTP extraction failed: {exc}"
        )

        return None

    finally:

        if http_capture is not None:

            try:
                http_capture.close()
            except:
                pass


def run_layer2_for_exported_flow(
    layer1_label,
    pcap_file
):

    if not should_run_layer2(
        layer1_label
    ):
        return None, None

    evidence = extract_http_request_from_pcap(
        pcap_file
    )

    if evidence is None:

        result = layer2_classifier.classify(
            None
        )

        return result.to_dict(), None

    result = layer2_classifier.classify_http_request(
        method=evidence["method"],
        path=evidence["path"],
        query=evidence["query"],
        body=evidence["body"],
        headers=evidence["headers"]
    )

    evidence_metadata = {
        "method": evidence["method"],
        "path": evidence["path"],
        "has_query": bool(
            evidence["query"]
        ),
        "has_body": bool(
            evidence["body"]
        ),
        "request_count": evidence[
            "request_count"
        ]
    }

    return (
        result.to_dict(),
        evidence_metadata
    )

# ==========================================================
# BATCH INFERENCE
# ==========================================================

def process_batch():

    global completed_flows

    if len(completed_flows) < FLOW_BATCH_SIZE:
        return

    print(
        f"\nProcessing {len(completed_flows)} flows..."
    )

    batch_packets = []

    for _, flow_data in completed_flows:

        batch_packets.extend(
            flow_data["packets"]
        )

    scapy_packets = []

    for pkt in batch_packets:

        try:

            raw = pkt.get_raw_packet()

            scapy_packets.append(
                Ether(
                    bytes(raw)
                )
            )

        except:
            pass

    temp_pcap = Path(
        tempfile.mktemp(
            suffix=".pcap"
        )
    )

    wrpcap(
        str(temp_pcap),
        scapy_packets
    )

    # ======================================
    # YOUR EXTRACTOR
    # ======================================

    features, flows = (
        extract_features_from_pcap(
            temp_pcap
        )
    )

    probabilities = (
        model.predict_proba(
            features
        )
    )

    top3_indices = np.argsort(
        probabilities,
        axis=1
    )[:, -3:][:, ::-1]

    report_rows = []

    flow_keys = list(
        flows.keys()
    )

    for flow_index in range(
        len(features)
    ):

        flow_key = flow_keys[
            flow_index
        ]

        row = {

            "flow_index":
                flow_index,

            "src_ip":
                flow_key[0],

            "dst_ip":
                flow_key[1],

            "src_port":
                flow_key[2],

            "dst_port":
                flow_key[3],

            "protocol":
                flow_key[4]
        }

        for rank, class_index in enumerate(
            top3_indices[flow_index],
            start=1
        ):

            label = (
                label_encoder
                .inverse_transform(
                    np.array(
                        [class_index]
                    )
                )[0]
            )

            row[
                f"top_{rank}_label"
            ] = label

            row[
                f"top_{rank}_probability"
            ] = float(
                probabilities[
                    flow_index,
                    class_index
                ]
            )

        report_rows.append(
            row
        )

    prediction_report = pd.DataFrame(
        report_rows
    )

    print(
        prediction_report[
            [
                "src_ip",
                "dst_ip",
                "top_1_label",
                "top_1_probability"
            ]
        ]
    )

    # ======================================
    # EXPORT REVIEW / ALERT FLOWS
    # ======================================

    for _, row in (
        prediction_report.iterrows()
    ):

        label = row[
            "top_1_label"
        ]

        confidence = float(
            row[
                "top_1_probability"
            ]
        )

        decision = decide(
            label,
            confidence
        )

        if decision == "BENIGN":
            continue

        flow_key = (
            row["src_ip"],
            row["dst_ip"],
            row["src_port"],
            row["dst_port"],
            row["protocol"]
        )

        packets = flows[
            flow_key
        ]

        timestamp = int(
            time.time()
        )

        pcap_file = (
            f"alerts/"
            f"{decision}_"
            f"{label}_"
            f"{confidence:.4f}_"
            f"{timestamp}.pcap"
        )

        export_flow_packets(
            packets,
            pcap_file
        )

        # Additive Layer 2 routing. Existing Layer 1 decision and PCAP
        # export behavior above is unchanged.
        layer2_result, http_evidence = (
            run_layer2_for_exported_flow(
                label,
                pcap_file
            )
        )

        metadata_file = (
            pcap_file.replace(
                ".pcap",
                ".json"
            )
        )

        metadata = {

            "decision":
                decision,

            "label":
                label,

            "confidence":
                confidence,

            "src_ip":
                row["src_ip"],

            "dst_ip":
                row["dst_ip"],

            "src_port":
                int(row["src_port"]),

            "dst_port":
                int(row["dst_port"]),

            "protocol":
                int(row["protocol"])
        }

        if layer2_result is not None:

            metadata["layer2"] = (
                layer2_result
            )

            metadata["http_evidence"] = (
                http_evidence
            )

        with open(
            metadata_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                metadata,
                f,
                indent=4
            )

        print(
            f"{decision} -> "
            f"{label} "
            f"{confidence:.4f}"
        )

        if layer2_result is not None:

            print(
                "LAYER2 -> "
                f"{layer2_result.get('label')} "
                f"status={layer2_result.get('status')} "
                f"confidence={layer2_result.get('confidence')}"
            )

    completed_flows = []

    try:
        temp_pcap.unlink()
    except:
        pass

# ==========================================================
# START CAPTURE
# ==========================================================

capture = pyshark.LiveCapture(
    interface=INTERFACE,
    tshark_path=TSHARK_PATH,
    include_raw=True,
    use_json=True
)

print(
    f"Listening on interface {INTERFACE}"
)

packet_counter = 0

for packet in capture.sniff_continuously():

    flow_key = get_flow_key(
        packet
    )

    if flow_key is None:
        continue

    now = time.time()

    if flow_key not in active_flows:

        active_flows[
            flow_key
        ] = {

            "packets": [],
            "last_seen": now
        }

    active_flows[
        flow_key
    ]["last_seen"] = now

    active_flows[
        flow_key
    ]["packets"].append(
        packet
    )

    packet_counter += 1

    if packet_counter % 10 == 0:
        print(f"Packets={packet_counter}")

    for key in list(
        active_flows.keys()
    ):

        idle = (
            now
            - active_flows[key]
            ["last_seen"]
        )

        if idle > FLOW_TIMEOUT:

            completed_flows.append(
                (
                    key,
                    active_flows[key]
                )
            )

            del active_flows[key]

    if packet_counter % 500 == 0:

        print(
            f"Packets={packet_counter} "
            f"Active={len(active_flows)} "
            f"Completed={len(completed_flows)}"
        )

    process_batch()