# live_soc.py

from pathlib import Path
import asyncio
import json
import re
import shutil
import tempfile
import time
import traceback

import joblib
import numpy as np
import pandas as pd
import pyshark

from scapy.all import Ether
from scapy.utils import wrpcap

from netflowautomationtest import extract_features_from_pcap
from layer2_runtime import Layer2PayloadClassifier

from behaviour_engine import (
    update_host_state,
    detect_behaviors,
)

from correlation_engine import correlate

from mitre.mitre_agent import (
    analyze_mitre,
    warm_up,
)


# ==========================================================
# ASYNCIO INITIALIZATION
# ==========================================================

try:
    asyncio.get_event_loop()
except RuntimeError:
    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(event_loop)


# ==========================================================
# CONFIG
# ==========================================================

INTERFACE = "en0"

FLOW_TIMEOUT = 3
FLOW_BATCH_SIZE = 100

REVIEW_THRESHOLD = 0.50
ALERT_THRESHOLD = 0.80

MITRE_ENABLED = True
MITRE_CANDIDATE_COUNT = 8
MITRE_WARMUP_ENABLED = True

# Ham analyze_mitre çıktısını terminalde gösterir.
MITRE_DEBUG = True

MODEL_PATH = Path("artifacts/xgb_nfv2_model.joblib")
ENCODER_PATH = Path("artifacts/label_encoder.joblib")

LAYER2_MODEL_PATH = Path(
    "models/payload_attack_classifier_v2.joblib"
)

ALERTS_DIRECTORY = Path("alerts")


# ==========================================================
# TSHARK PATH
# ==========================================================

def find_tshark():
    candidates = [
        shutil.which("tshark"),
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]

    for candidate in candidates:
        if not candidate:
            continue

        candidate_path = Path(candidate)

        if candidate_path.exists():
            return str(candidate_path)

    raise FileNotFoundError(
        "tshark bulunamadı. Wireshark/tshark kurulumunu ve PATH "
        "ayarını kontrol et."
    )


TSHARK_PATH = find_tshark()


# ==========================================================
# STARTUP VALIDATION
# ==========================================================

def validate_required_files():
    required_files = [
        MODEL_PATH,
        ENCODER_PATH,
        LAYER2_MODEL_PATH,
    ]

    missing_files = [
        str(file_path)
        for file_path in required_files
        if not file_path.exists()
    ]

    if missing_files:
        raise FileNotFoundError(
            "Gerekli model dosyaları bulunamadı:\n"
            + "\n".join(missing_files)
        )


validate_required_files()

ALERTS_DIRECTORY.mkdir(
    parents=True,
    exist_ok=True,
)


# ==========================================================
# LOAD MODELS
# ==========================================================

print("Loading Layer 1 model...")

model = joblib.load(MODEL_PATH)
label_encoder = joblib.load(ENCODER_PATH)

print("Loading Layer 2 payload model...")

layer2_classifier = Layer2PayloadClassifier(
    model_path=str(LAYER2_MODEL_PATH),
    confidence_threshold=0.80,
    max_payload_length=16384,
    decode_payload=True,
)


# ==========================================================
# LAYER 2 ROUTING
# ==========================================================

LAYER2_WEB_LABELS = {
    "web attack",
    "web_attack",
    "webattack",
}


# ==========================================================
# FLOW STORAGE
# ==========================================================

active_flows = {}
completed_flows = []


# ==========================================================
# GENERAL HELPERS
# ==========================================================

def safe_json_value(value):
    if isinstance(value, dict):
        return {
            str(key): safe_json_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            safe_json_value(item)
            for item in value
        ]

    if isinstance(value, np.ndarray):
        return [
            safe_json_value(item)
            for item in value.tolist()
        ]

    if isinstance(value, np.generic):
        return value.item()

    if isinstance(value, Path):
        return str(value)

    return value


def safe_filename(value):
    text = str(value).strip()

    text = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        text,
    )

    text = text.strip("._")

    return text or "unknown"


def create_alert_base_path(
        decision,
        label,
        confidence,
):
    timestamp_ns = time.time_ns()

    confidence_text = (
        f"{float(confidence):.4f}"
        .replace(".", "_")
    )

    filename = (
        f"{safe_filename(decision)}_"
        f"{safe_filename(label)}_"
        f"{confidence_text}_"
        f"{timestamp_ns}"
    )

    return ALERTS_DIRECTORY / filename


def decode_json_if_possible(value):
    if not isinstance(value, str):
        return value

    text = value.strip()

    if not text:
        return value

    # ```json ... ``` temizliği
    if text.startswith("```"):
        text = re.sub(
            r"^```(?:json)?\s*",
            "",
            text,
            flags=re.IGNORECASE,
        )

        text = re.sub(
            r"\s*```$",
            "",
            text,
        )

        text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Model cevabının içindeki ilk JSON nesnesini dene.
    first_brace = text.find("{")
    last_brace = text.rfind("}")

    if (
        first_brace != -1
        and last_brace != -1
        and last_brace > first_brace
    ):
        json_candidate = text[
            first_brace:last_brace + 1
        ]

        try:
            return json.loads(json_candidate)
        except json.JSONDecodeError:
            pass

    return value


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

            sport = int(packet.tcp.srcport)
            dport = int(packet.tcp.dstport)

        elif proto == 17:
            if not hasattr(packet, "udp"):
                return None

            sport = int(packet.udp.srcport)
            dport = int(packet.udp.dstport)

        else:
            return None

        return (
            str(packet.ip.src),
            str(packet.ip.dst),
            sport,
            dport,
            proto,
        )

    except Exception:
        return None


# ==========================================================
# DECISION
# ==========================================================

def decide(label, confidence):
    normalized_label = str(label).strip().lower()

    if normalized_label == "benign":
        return "BENIGN"

    if confidence < ALERT_THRESHOLD:
        return "REVIEW"

    return "ALERT"


# ==========================================================
# PCAP EXPORT
# ==========================================================

def convert_to_scapy_packets(packets):
    scapy_packets = []

    for packet in packets:
        try:
            if isinstance(
                    packet,
                    (bytes, bytearray)
            ):
                raw_packet = bytes(packet)

            elif hasattr(
                    packet,
                    "get_raw_packet"
            ):
                raw_packet = bytes(
                    packet.get_raw_packet()
                )

            else:
                continue

            if not raw_packet:
                continue

            scapy_packets.append(
                Ether(raw_packet)
            )

        except Exception as exc:
            print(
                "SCAPY CONVERSION FAILED ->",
                repr(exc)
            )

    return scapy_packets



def export_flow_packets(
        packets,
        output_file,
):
    output_path = Path(output_file)

    scapy_packets = convert_to_scapy_packets(
        packets
    )

    if not scapy_packets:
        print(
            "PCAP EXPORT WARNING -> "
            f"No raw packets available for {output_path}"
        )
        return False

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    wrpcap(
        str(output_path),
        scapy_packets
    )

    if (
        not output_path.exists()
        or output_path.stat().st_size == 0
    ):
        print(
            "PCAP EXPORT FAILED ->",
            output_path
        )
        return False

    print(
        "PCAP EXPORTED ->",
        output_path,
        f"packets={len(scapy_packets)}",
        f"bytes={output_path.stat().st_size}"
    )

    return True


# ==========================================================
# LAYER 2
# ==========================================================

def normalize_layer2_label(label):
    return (
        str(label)
        .strip()
        .lower()
        .replace("-", "_")
    )


def should_run_layer2(label):
    normalized_label = normalize_layer2_label(
        label
    )

    return normalized_label in LAYER2_WEB_LABELS


def extract_http_request_from_pcap(pcap_file):
    """
    Best-effort plaintext HTTP request extraction.

    HTTPS içeriği daha önce çözülmediyse burada görülemez.
    """

    pcap_path = Path(pcap_file)

    if not pcap_path.exists():
        print(
            "LAYER2 HTTP extraction skipped: "
            f"PCAP not found: {pcap_path}"
        )
        return None

    if pcap_path.stat().st_size == 0:
        print(
            "LAYER2 HTTP extraction skipped: "
            f"PCAP is empty: {pcap_path}"
        )
        return None

    http_capture = None

    try:
        http_capture = pyshark.FileCapture(
            str(pcap_path),
            tshark_path=TSHARK_PATH,
            display_filter="http.request",
            keep_packets=False,
            use_json=True,
        )

        requests = []

        for packet in http_capture:
            if not hasattr(packet, "http"):
                continue

            http_layer = packet.http

            method = getattr(
                http_layer,
                "request_method",
                None,
            )

            uri = getattr(
                http_layer,
                "request_uri",
                None,
            )

            full_uri = getattr(
                http_layer,
                "request_full_uri",
                None,
            )

            body = getattr(
                http_layer,
                "file_data",
                None,
            )

            if body is None:
                body = getattr(
                    http_layer,
                    "request_body",
                    None,
                )

            uri_text = str(
                full_uri or uri or ""
            )

            path = None
            query = None

            if uri_text:
                if "?" in uri_text:
                    path, query = uri_text.split(
                        "?",
                        1,
                    )
                else:
                    path = uri_text

            headers = {}

            content_type = getattr(
                http_layer,
                "content_type",
                None,
            )

            user_agent = getattr(
                http_layer,
                "user_agent",
                None,
            )

            referer = getattr(
                http_layer,
                "referer",
                None,
            )

            host = getattr(
                http_layer,
                "host",
                None,
            )

            if content_type:
                headers["content-type"] = str(
                    content_type
                )

            if user_agent:
                headers["user-agent"] = str(
                    user_agent
                )

            if referer:
                headers["referer"] = str(
                    referer
                )

            if host:
                headers["host"] = str(host)

            if any(
                [
                    method,
                    path,
                    query,
                    body,
                ]
            ):
                requests.append(
                    {
                        "method": (
                            str(method)
                            if method
                            else None
                        ),
                        "path": path,
                        "query": query,
                        "body": (
                            str(body)
                            if body
                            else None
                        ),
                        "headers": headers,
                    }
                )

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

        combined_headers = {}

        for item in requests:
            combined_headers.update(
                item.get(
                    "headers",
                    {},
                )
            )

        return {
            "method": (
                methods[0]
                if methods
                else None
            ),
            "path": (
                "\n".join(paths)
                if paths
                else None
            ),
            "query": (
                "\n".join(queries)
                if queries
                else None
            ),
            "body": (
                "\n".join(bodies)
                if bodies
                else None
            ),
            "headers": combined_headers,
            "request_count": len(requests),
        }

    except Exception as exc:
        print(
            "LAYER2 HTTP extraction failed ->",
            repr(exc),
        )

        return None

    finally:
        if http_capture is not None:
            try:
                http_capture.close()
            except Exception:
                pass


def run_layer2_for_exported_flow(
        layer1_label,
        pcap_file,
):
    if not should_run_layer2(layer1_label):
        return None, None

    evidence = extract_http_request_from_pcap(
        pcap_file
    )

    if evidence is None:
        result = layer2_classifier.classify(
            None
        )

        return result.to_dict(), None

    result = (
        layer2_classifier.classify_http_request(
            method=evidence["method"],
            path=evidence["path"],
            query=evidence["query"],
            body=evidence["body"],
            headers=evidence["headers"],
        )
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
        ],
    }

    return (
        result.to_dict(),
        evidence_metadata,
    )


# ==========================================================
# MITRE RESULT NORMALIZATION
# ==========================================================

def normalize_technique(technique):
    technique = decode_json_if_possible(
        technique
    )

    if isinstance(technique, str):
        technique_id_match = re.search(
            r"\bT\d{4}(?:\.\d{3})?\b",
            technique,
            flags=re.IGNORECASE,
        )

        if not technique_id_match:
            return None

        return {
            "id": (
                technique_id_match
                .group(0)
                .upper()
            ),
            "name": "",
            "confidence": 0.0,
            "reason": technique,
        }

    if not isinstance(technique, dict):
        return None

    technique_id = (
        technique.get("id")
        or technique.get("technique_id")
        or technique.get("attack_id")
        or technique.get("external_id")
        or technique.get("mitre_id")
    )

    name = (
        technique.get("name")
        or technique.get("technique_name")
        or technique.get("title")
        or ""
    )

    confidence = technique.get(
        "confidence",
        technique.get(
            "score",
            technique.get(
                "probability",
                0.0,
            ),
        ),
    )

    reason = (
        technique.get("reason")
        or technique.get("rationale")
        or technique.get("explanation")
        or ""
    )

    if not technique_id:
        return None

    technique_id = str(
        technique_id
    ).strip().upper()

    if not re.fullmatch(
        r"T\d{4}(?:\.\d{3})?",
        technique_id,
    ):
        return None

    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0

    if confidence > 1.0 and confidence <= 100.0:
        confidence = confidence / 100.0

    confidence = max(
        0.0,
        min(1.0, confidence),
    )

    return {
        "id": technique_id,
        "name": str(name),
        "confidence": confidence,
        "reason": str(reason),
    }


def find_technique_list(value, depth=0):
    if depth > 8:
        return []

    value = decode_json_if_possible(value)

    if isinstance(value, list):
        normalized = []

        for item in value:
            technique = normalize_technique(item)

            if technique is not None:
                normalized.append(technique)

        if normalized:
            return normalized

        for item in value:
            nested = find_technique_list(
                item,
                depth + 1,
            )

            if nested:
                return nested

        return []

    if not isinstance(value, dict):
        return []

    technique_keys = [
        "techniques",
        "mitre_techniques",
        "attack_techniques",
        "selected_techniques",
        "matches",
    ]

    for key in technique_keys:
        if key not in value:
            continue

        nested = find_technique_list(
            value[key],
            depth + 1,
        )

        if nested:
            return nested

    nested_container_keys = [
        "result",
        "response",
        "output",
        "analysis",
        "parsed_result",
        "data",
        "message",
        "content",
    ]

    for key in nested_container_keys:
        if key not in value:
            continue

        nested = find_technique_list(
            value[key],
            depth + 1,
        )

        if nested:
            return nested

    direct_technique = normalize_technique(
        value
    )

    if direct_technique is not None:
        return [direct_technique]

    return []


def deduplicate_techniques(techniques):
    unique = {}

    for technique in techniques:
        technique_id = technique.get("id")

        if not technique_id:
            continue

        existing = unique.get(technique_id)

        if existing is None:
            unique[technique_id] = technique
            continue

        if (
            technique.get("confidence", 0.0)
            > existing.get("confidence", 0.0)
        ):
            unique[technique_id] = technique

    return list(unique.values())


def normalize_mitre_result(mitre_output):
    decoded_output = decode_json_if_possible(
        mitre_output
    )

    techniques = find_technique_list(
        decoded_output
    )

    techniques = deduplicate_techniques(
        techniques
    )

    return {
        "techniques": techniques
    }


def get_mitre_candidates(mitre_output):
    if not isinstance(mitre_output, dict):
        return []

    candidates = mitre_output.get(
        "candidates",
        [],
    )

    candidates = decode_json_if_possible(
        candidates
    )

    if isinstance(candidates, list):
        return candidates

    if candidates:
        return [candidates]

    return []


# ==========================================================
# MITRE ATT&CK ANALYSIS
# ==========================================================

def run_mitre_analysis(
        layer1_label,
        layer1_confidence,
        behavioral_findings,
        correlation_data,
        flow_info=None,
        layer2_result=None,
        http_evidence=None,
):
    flow_info = (
        flow_info
        if isinstance(flow_info, dict)
        else {}
    )

    layer2_result = (
        layer2_result
        if isinstance(layer2_result, dict)
        else {}
    )

    http_evidence = (
        http_evidence
        if isinstance(http_evidence, dict)
        else {}
    )
    if not MITRE_ENABLED:
        return {
            "status": "disabled",
            "result": {
                "techniques": []
            },
            "candidates": [],
        }

    if not behavioral_findings:
        behavioral_findings = [
            {
                "behavior": (
                    str(layer1_label)
                    .lower()
                    .replace(" ", "_")
                ),
                "confidence": float(
                    layer1_confidence
                ),
                "score": int(
                    float(layer1_confidence)
                    * 100
                ),
                "evidence": {},
            }
        ]

    started = time.perf_counter()

    try:
        mitre_output = analyze_mitre(
            attack_label=str(layer1_label),
            confidence=float(
                layer1_confidence
            ),
            behavioral_findings=(
                behavioral_findings
            ),
            host_state={
                "correlation_risk_score": (
                    correlation_data.get(
                        "risk_score",
                        0,
                    )
                ),
                "correlation_severity": (
                    correlation_data.get(
                        "severity",
                        "informational",
                    )
                ),
                "suspicious_activity": (
                    correlation_data.get(
                        "suspicious_activity",
                        False,
                    )
                ),

                # Flow evidence
                "src_ip": flow_info.get("src_ip"),
                "dst_ip": flow_info.get("dst_ip"),
                "src_port": flow_info.get("src_port"),
                "dst_port": flow_info.get("dst_port"),
                "protocol": flow_info.get("protocol"),
                "flow_timestamp": flow_info.get("timestamp"),

                # Layer 2 evidence
                "layer2_label": layer2_result.get("label"),
                "layer2_confidence": layer2_result.get(
                    "confidence"
                ),
                "layer2_status": layer2_result.get("status"),

                # HTTP evidence
                "http_method": http_evidence.get("method"),
                "http_path": http_evidence.get("path"),
                "http_has_query": http_evidence.get(
                    "has_query",
                    False,
                ),
                "http_has_body": http_evidence.get(
                    "has_body",
                    False,
                ),
                "http_request_count": http_evidence.get(
                    "request_count",
                    0,
                ),
            },
            candidate_count=(
                MITRE_CANDIDATE_COUNT
            ),
        )

        elapsed = (
            time.perf_counter()
            - started
        )

        if mitre_output is None:
            mitre_output = {}

        decoded_output = decode_json_if_possible(
            mitre_output
        )

        normalized_result = normalize_mitre_result(
            decoded_output
        )

        candidates = get_mitre_candidates(
            decoded_output
        )

        techniques = normalized_result.get(
            "techniques",
            [],
        )

        if MITRE_DEBUG:
            print(
                "\n"
                "========== MITRE RAW OUTPUT =========="
            )

            try:
                print(
                    json.dumps(
                        safe_json_value(
                            decoded_output
                        ),
                        indent=2,
                        ensure_ascii=False,
                    )
                )
            except Exception:
                print(repr(decoded_output))

            print(
                "MITRE CANDIDATE COUNT ->",
                len(candidates),
            )

            print(
                "MITRE TECHNIQUE COUNT ->",
                len(techniques),
            )

            print(
                "======================================"
                "\n"
            )

        if techniques:
            status = "completed"
            error_message = None

        elif not candidates:
            status = "empty_candidates"
            error_message = (
                "MITRE retriever returned no candidates."
            )

        else:
            status = "insufficient_evidence"
            error_message = (
                "MITRE candidates were retrieved, but the available "
                "network-flow evidence was not specific enough to "
                "select a technique reliably."
            )

        output_dictionary = (
            decoded_output
            if isinstance(decoded_output, dict)
            else {}
        )

        response = {
            "status": status,
            "result": normalized_result,
            "candidates": candidates,
            "timing": {
                "retrieval_seconds": float(
                    output_dictionary.get(
                        "retrieval_seconds",
                        0.0,
                    )
                    or 0.0
                ),
                "qwen_seconds": float(
                    output_dictionary.get(
                        "qwen_seconds",
                        0.0,
                    )
                    or 0.0
                ),
                "total_seconds": float(
                    output_dictionary.get(
                        "elapsed_seconds",
                        elapsed,
                    )
                    or elapsed
                ),
            },
            "ollama_metrics": (
                output_dictionary.get(
                    "ollama_metrics",
                    {},
                )
            ),
            "raw_output": safe_json_value(
                decoded_output
            ),
        }

        if error_message:
            response["message"] = error_message

        return response

    except Exception as exc:
        elapsed = (
            time.perf_counter()
            - started
        )

        print(
            "MITRE ANALYSIS FAILED ->",
            repr(exc),
        )

        traceback.print_exc()

        return {
            "status": "error",
            "error": str(exc),
            "error_type": type(exc).__name__,
            "result": {
                "techniques": []
            },
            "candidates": [],
            "timing": {
                "retrieval_seconds": 0.0,
                "qwen_seconds": 0.0,
                "total_seconds": elapsed,
            },
        }


# ==========================================================
# MITRE CONSOLE OUTPUT
# ==========================================================

def print_mitre_analysis(mitre_analysis):
    if mitre_analysis is None:
        print(
            "MITRE -> status=not_run"
        )
        return

    status = mitre_analysis.get(
        "status",
        "unknown",
    )

    result = mitre_analysis.get(
        "result",
        {},
    )

    techniques = result.get(
        "techniques",
        [],
    )

    candidates = mitre_analysis.get(
        "candidates",
        [],
    )

    print(
        "MITRE ->",
        f"status={status}",
        f"candidates={len(candidates)}",
        f"techniques={len(techniques)}",
    )

    if mitre_analysis.get("message"):
        print(
            "MITRE MESSAGE ->",
            mitre_analysis["message"],
        )

    if mitre_analysis.get("error"):
        print(
            "MITRE ERROR ->",
            mitre_analysis["error"],
        )

    if not techniques:
        print(
            "MITRE RESULT -> "
            "No technique produced."
        )

    for technique in techniques:
        print(
            "MITRE TECHNIQUE ->",
            technique.get(
                "id",
                "UNKNOWN",
            ),
            technique.get(
                "name",
                "",
            ),
            "confidence=",
            technique.get(
                "confidence",
                0.0,
            ),
            "reason=",
            technique.get(
                "reason",
                "",
            ),
        )

    timing = mitre_analysis.get(
        "timing",
        {},
    )

    if timing:
        print(
            "MITRE TIMING ->",
            "retrieval="
            f"{timing.get('retrieval_seconds', 0.0):.4f}s",
            "qwen="
            f"{timing.get('qwen_seconds', 0.0):.4f}s",
            "total="
            f"{timing.get('total_seconds', 0.0):.4f}s",
        )


# ==========================================================
# ALERT WRITING
# ==========================================================

def write_alert_metadata(
        metadata_file,
        metadata,
):
    metadata_path = Path(metadata_file)

    metadata_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with metadata_path.open(
        "w",
        encoding="utf-8",
    ) as output_file:
        json.dump(
            safe_json_value(metadata),
            output_file,
            indent=4,
            ensure_ascii=False,
        )


# ==========================================================
# SINGLE PREDICTION PROCESSING
# ==========================================================

def process_prediction_row(
        row,
        flows,
):
    label = str(
        row["top_1_label"]
    )

    confidence = float(
        row["top_1_probability"]
    )

    src_ip = str(row["src_ip"])
    dst_ip = str(row["dst_ip"])

    src_port = int(row["src_port"])
    dst_port = int(row["dst_port"])
    protocol = int(row["protocol"])

    flow_info = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "timestamp": time.time(),
    }

    update_host_state(flow_info)

    behavioral_findings = detect_behaviors(
        src_ip
    )

    if behavioral_findings is None:
        behavioral_findings = []

    decision = decide(
        label,
        confidence,
    )

    flow_key = (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
    )

    packets = flows.get(flow_key)

    if packets is None:
        print(
            "FLOW WARNING -> "
            f"Flow key not found: {flow_key}"
        )
        return

    layer2_result = None
    http_evidence = None
    pcap_file = None

    if decision != "BENIGN":
        base_path = create_alert_base_path(
            decision,
            label,
            confidence,
        )

        pcap_file = base_path.with_suffix(
            ".pcap"
        )

        export_success = export_flow_packets(
            packets,
            pcap_file,
        )

        if export_success:
            layer2_result, http_evidence = (
                run_layer2_for_exported_flow(
                    label,
                    pcap_file,
                )
            )
        else:
            print(
                "LAYER2 skipped because flow "
                "PCAP could not be exported."
            )

    xgb_result = {
        "label": label,
        "confidence": confidence,
    }

    correlation_data = correlate(
        xgb_result=xgb_result,
        payload_result=layer2_result,
        behavioral_findings=(
            behavioral_findings
        ),
    )

    if not isinstance(correlation_data, dict):
        correlation_data = {
            "suspicious_activity": False,
            "risk_score": 0,
            "severity": "informational",
            "raw_result": safe_json_value(
                correlation_data
            ),
        }

    is_suspicious = bool(
        correlation_data.get(
            "suspicious_activity",
            False,
        )
    )

    if (
        decision == "BENIGN"
        and not is_suspicious
    ):
        return

    if decision == "BENIGN":
        decision = "BEHAVIOR_ALERT"

        base_path = create_alert_base_path(
            decision,
            label,
            confidence,
        )

        pcap_file = base_path.with_suffix(
            ".pcap"
        )

        export_flow_packets(
            packets,
            pcap_file,
        )

    if pcap_file is None:
        print(
            "ALERT ERROR -> "
            "PCAP path was not created."
        )
        return

    mitre_analysis = run_mitre_analysis(
        layer1_label=label,
        layer1_confidence=confidence,
        behavioral_findings=(
            behavioral_findings
        ),
        correlation_data=correlation_data,
    )

    metadata_file = pcap_file.with_suffix(
        ".json"
    )

    metadata = {
        "decision": decision,
        "label": label,
        "confidence": confidence,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "pcap_file": str(pcap_file),
        "correlation_summary": (
            correlation_data
        ),
        "behavioral_findings": (
            behavioral_findings
        ),
        "mitre_analysis": (
            mitre_analysis
        ),
    }

    if layer2_result is not None:
        metadata["layer2"] = (
            layer2_result
        )

        metadata["http_evidence"] = (
            http_evidence
        )

    write_alert_metadata(
        metadata_file,
        metadata,
    )

    print(
        f"{decision} -> "
        f"{label} "
        f"{confidence:.4f} "
        f"| Risk: "
        f"{correlation_data.get('risk_score', 0)} "
        f"("
        f"{correlation_data.get('severity', 'informational')}"
        f")"
    )

    if layer2_result is not None:
        print(
            "LAYER2 -> "
            f"{layer2_result.get('label')} "
            f"status="
            f"{layer2_result.get('status')} "
            f"confidence="
            f"{layer2_result.get('confidence')}"
        )

    if behavioral_findings:
        print(
            "BEHAVIOR -> "
            f"{len(behavioral_findings)} "
            f"anomalies detected for {src_ip}"
        )

    print_mitre_analysis(
        mitre_analysis
    )

    print(
        "METADATA ->",
        metadata_file,
    )


# ==========================================================
# BATCH INFERENCE
# ==========================================================

def process_batch():
    global completed_flows

    if len(completed_flows) < FLOW_BATCH_SIZE:
        return

    flows_to_process = completed_flows[
        :FLOW_BATCH_SIZE
    ]

    completed_flows = completed_flows[
        FLOW_BATCH_SIZE:
    ]

    print(
        "\nProcessing "
        f"{len(flows_to_process)} flows..."
    )

    temp_pcap_path = None

    try:
        batch_packets = []

        for _, flow_data in flows_to_process:
            batch_packets.extend(
                flow_data.get(
                    "packets",
                    [],
                )
            )

        scapy_packets = convert_to_scapy_packets(
            batch_packets
        )

        if not scapy_packets:
            print(
                "BATCH SKIPPED -> "
                "No raw packets could be converted."
            )
            return

        with tempfile.NamedTemporaryFile(
                suffix=".pcap",
                delete=False,
        ) as temp_file:
            temp_pcap_path = Path(
                temp_file.name
            )

        wrpcap(
            str(temp_pcap_path),
            scapy_packets,
        )

        if (
            not temp_pcap_path.exists()
            or temp_pcap_path.stat().st_size == 0
        ):
            print(
                "BATCH SKIPPED -> "
                "Temporary PCAP is empty."
            )
            return

        features, flows = (
            extract_features_from_pcap(
                temp_pcap_path
            )
        )

        if features is None:
            print(
                "BATCH SKIPPED -> "
                "Extractor returned features=None."
            )
            return

        if flows is None:
            print(
                "BATCH SKIPPED -> "
                "Extractor returned flows=None."
            )
            return

        if len(features) == 0:
            print(
                "BATCH SKIPPED -> "
                "Extractor returned zero features."
            )
            return

        if len(flows) == 0:
            print(
                "BATCH SKIPPED -> "
                "Extractor returned zero flows."
            )
            return

        flow_keys = list(flows.keys())

        if len(features) != len(flow_keys):
            print(
                "BATCH ERROR -> "
                "Feature count and flow count differ: "
                f"features={len(features)}, "
                f"flows={len(flow_keys)}"
            )
            return

        probabilities = model.predict_proba(
            features
        )

        if len(probabilities) != len(features):
            print(
                "BATCH ERROR -> "
                "Prediction count and feature count differ."
            )
            return

        class_count = probabilities.shape[1]
        top_count = min(3, class_count)

        top_indices = np.argsort(
            probabilities,
            axis=1,
        )[:, -top_count:][:, ::-1]

        report_rows = []

        for flow_index in range(
                len(features)
        ):
            flow_key = flow_keys[
                flow_index
            ]

            row = {
                "flow_index": flow_index,
                "src_ip": str(flow_key[0]),
                "dst_ip": str(flow_key[1]),
                "src_port": int(flow_key[2]),
                "dst_port": int(flow_key[3]),
                "protocol": int(flow_key[4]),
            }

            for rank, class_index in enumerate(
                    top_indices[flow_index],
                    start=1,
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
                ] = str(label)

                row[
                    f"top_{rank}_probability"
                ] = float(
                    probabilities[
                        flow_index,
                        class_index,
                    ]
                )

            report_rows.append(row)

        prediction_report = pd.DataFrame(
            report_rows
        )

        print(
            prediction_report[
                [
                    "src_ip",
                    "dst_ip",
                    "top_1_label",
                    "top_1_probability",
                ]
            ]
        )

        for _, row in (
                prediction_report.iterrows()
        ):
            try:
                process_prediction_row(
                    row,
                    flows,
                )

            except Exception as exc:
                print(
                    "FLOW PROCESSING FAILED ->",
                    repr(exc),
                )

                traceback.print_exc()

    except Exception as exc:
        print(
            "BATCH PROCESSING FAILED ->",
            repr(exc),
        )

        traceback.print_exc()

    finally:
        if (
            temp_pcap_path is not None
            and temp_pcap_path.exists()
        ):
            try:
                temp_pcap_path.unlink()
            except Exception as exc:
                print(
                    "TEMP PCAP CLEANUP WARNING ->",
                    repr(exc),
                )


# ==========================================================
# MITRE / QWEN WARM-UP
# ==========================================================

def warm_up_mitre():
    if not MITRE_ENABLED:
        print("MITRE integration disabled.")
        return

    if not MITRE_WARMUP_ENABLED:
        print("MITRE warm-up disabled.")
        return

    try:
        print(
            "Warming up local MITRE Qwen model..."
        )

        warmup_seconds = warm_up()

        print(
            "MITRE model warmed up in "
            f"{float(warmup_seconds):.2f} sec"
        )

    except Exception as exc:
        print(
            "MITRE warm-up failed. "
            "Live SOC will continue ->",
            repr(exc),
        )

        traceback.print_exc()


# ==========================================================
# LIVE CAPTURE
# ==========================================================

def run_live_capture():
    print(
        "Configuration:"
    )

    print(
        f"  Interface: {INTERFACE}"
    )

    print(
        f"  Tshark: {TSHARK_PATH}"
    )

    print(
        f"  Flow timeout: {FLOW_TIMEOUT}s"
    )

    print(
        f"  Batch size: {FLOW_BATCH_SIZE}"
    )

    print(
        f"  MITRE enabled: {MITRE_ENABLED}"
    )

    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        tshark_path=TSHARK_PATH,
        include_raw=True,
        use_json=True,
    )

    print(
        f"Listening on interface {INTERFACE}"
    )

    packet_counter = 0

    try:
        for packet in capture.sniff_continuously():
            flow_key = get_flow_key(packet)

            if flow_key is None:
                continue

            now = time.time()

            if flow_key not in active_flows:
                active_flows[flow_key] = {
                    "packets": [],
                    "last_seen": now,
                }

            active_flows[
                flow_key
            ]["last_seen"] = now

            try:
                raw_packet = packet.get_raw_packet()

                if raw_packet:
                    active_flows[
                        flow_key
                    ]["packets"].append(
                        bytes(raw_packet)
                    )

            except Exception as exc:
                print(
                    "RAW PACKET EXTRACTION FAILED ->",
                    repr(exc)
                )
                continue

            packet_counter += 1

            if packet_counter % 10 == 0:
                print(
                    f"Packets={packet_counter}",
                    end="\r",
                    flush=True,
                )

            for key in list(
                    active_flows.keys()
            ):
                idle_seconds = (
                    now
                    - active_flows[
                        key
                    ]["last_seen"]
                )

                if idle_seconds > FLOW_TIMEOUT:
                    completed_flows.append(
                        (
                            key,
                            active_flows[key],
                        )
                    )

                    del active_flows[key]

            if packet_counter % 500 == 0:
                print()

                print(
                    f"Packets={packet_counter} "
                    f"Active={len(active_flows)} "
                    f"Completed={len(completed_flows)}"
                )

            while (
                len(completed_flows)
                >= FLOW_BATCH_SIZE
            ):
                process_batch()

    except KeyboardInterrupt:
        print(
            "\nLive capture stopped by user."
        )

    except Exception as exc:
        print(
            "\nLIVE CAPTURE FAILED ->",
            repr(exc),
        )

        traceback.print_exc()

    finally:
        try:
            capture.close()
        except Exception:
            pass


# ==========================================================
# MAIN
# ==========================================================

def main():
    print(
        "Layer 1 classes ->",
        list(label_encoder.classes_),
    )

    warm_up_mitre()
    run_live_capture()


if __name__ == "__main__":
    main()