# live_soc.py
"""
Yeni mimari:

    Flow
     -> Layer 1 (XGBoost)
     -> Layer 2 (web payload, gerekirse)
     -> Behavior + Correlation
     -> Qwen THREAT VALIDATOR  ("gerçekten saldırı mı?")
     -> Malicious / Suspicious(yüksek güven) ?
            -> MITRE (yalnızca network-observable teknikler)
            -> Action

MITRE artık karar vermez; saldırı doğrulandıktan sonra (otomatik veya
dashboard'daki butonla) aksiyon/açıklama için çalışır.

Karar iyileştirmeleri:
  1) Akış telemetrisi (süre, hacim, hız, TCP bayrakları) validator
     bağlamına eklenir.
  2) HTTP yanıt kodları (401/403/404/500 ...) kanıta eklenir.
  3) Cache imzası query/body hash'i ve yanıt kodlarını içerir.
  4) Kaynak cooldown'u, payload/davranış kanıtı varsa bypass edilir.
  5) HTTP çıkarımı birden fazla standart dışı porta genişletildi.
"""

from pathlib import Path
import asyncio
import copy
import hashlib
import inspect
import ipaddress
import itertools
import json
import os
import queue
import re
import shutil
import sys
import tempfile
import threading
import time
import traceback
import uuid
import warnings
from collections import Counter, defaultdict, deque

import joblib
import numpy as np
import pandas as pd
import pyshark

from scapy.all import Ether, IP, TCP, UDP
from scapy.utils import wrpcap

# ==========================================================
# PROJECT PATHS
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from netflowautomationtest import extract_features_from_pcap
from layer2_runtime import Layer2PayloadClassifier

from behaviour_engine import (
    update_host_state,
    detect_behaviors,
)

from correlation_engine import correlate

from threat_validator import (
    build_validation_context,
    validate_threat,
    is_attack_verdict,
    warm_up_validator,
    VALIDATOR_MODEL,
)

from mitre_runner import (
    run_mitre_analysis,
    skipped_mitre,
    warm_up_mitre_engine,
    safe_json_value,
)

from action_agent import (
    run_action_agent,
    skipped_action,
)


# ==========================================================
# ASYNCIO INITIALIZATION
# ==========================================================

def _pyshark_loop_exception_handler(loop, context):
    exc = context.get("exception")
    if isinstance(exc, (EOFError, asyncio.CancelledError)):
        return
    loop.default_exception_handler(context)


def ensure_event_loop():
    """
    PyShark 0.6 LiveCapture/FileCapture bir asyncio event loop ister.
    Python 3.12+ üzerinde loop açıkça oluşturulur ve capture'a verilir.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            loop = asyncio.get_event_loop()

        if loop.is_closed():
            raise RuntimeError("event loop is closed")

    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    loop.set_exception_handler(_pyshark_loop_exception_handler)
    return loop


event_loop = ensure_event_loop()


# ==========================================================
# CONFIG
# ==========================================================

INTERFACE = ["en0", "lo0"]

FLOW_TIMEOUT = 10
FLOW_BATCH_SIZE = 100

REVIEW_THRESHOLD = 0.50
ALERT_THRESHOLD = 0.80

CAPTURE_BPF_FILTER = None
PRESERVE_CAPTURE_TIMESTAMPS = False

MODEL_PATH = BASE_DIR / "artifacts" / "xgb_nfv2_model.joblib"
ENCODER_PATH = BASE_DIR / "artifacts" / "label_encoder.joblib"

LAYER2_MODEL_PATH = (
    BASE_DIR / "models" / "payload_attack_classifier_v2.joblib"
)

ALERTS_DIRECTORY = BASE_DIR / "alerts"


# ==========================================================
# THREAT VALIDATOR / MITRE CONFIG
# ==========================================================

# "auto"      -> kanıt kapısını geçen alert'ler Qwen'e otomatik gider
# "on_demand" -> Qwen hiç otomatik çağrılmaz; dashboard'daki
#                "AI'a Sor" butonu ile çalışır (en hızlı canlı akış)
# "off"       -> doğrulama yok
VALIDATOR_MODE = "auto"
VALIDATOR_WARMUP_ENABLED = True

# "auto"      -> verdict Malicious / Suspicious(>= eşik) ise MITRE otomatik
# "on_demand" -> MITRE yalnızca dashboard'daki "MITRE Eşle" butonuyla
# "off"       -> MITRE hiç çalışmaz
MITRE_MODE = "auto"
MITRE_WARMUP_ENABLED = False
MITRE_DEBUG = False

# "auto"      -> doğrulanmış saldırıda Action Agent otomatik çalışır
# "on_demand" -> Action Agent yalnızca dashboard'daki "Aksiyon Al" butonuyla
# "off"       -> Action Agent hiç çalışmaz
ACTION_MODE = "auto"

# True: Qwen Validator + MITRE + Action Agent arka plan kuyruğunda (worker thread)
#       asenkron çalışır; paket yakalama döngüsü hiç bloklanmaz ve buffer'da paket kaybolmaz!
ASYNC_LLM_PIPELINE = True

# Suspicious verdict'in MITRE'ye geçmesi için minimum Qwen güveni.
SUSPICIOUS_MITRE_MIN_CONFIDENCE = 0.80

# Kanıt kapısı (eskiden MITRE kapısıydı, şimdi validator kapısı).
VALIDATOR_MIN_CONFIDENCE = 0.80
VALIDATOR_MIN_SEVERITY = "medium"
VALIDATOR_MIN_RISK_SCORE = 40

# Aynı kanıt imzası için sonucu ne kadar süre yeniden kullan (saniye).
ASSESSMENT_CACHE_TTL = 120
ASSESSMENT_CACHE_MAX_ENTRIES = 512

# Aynı kaynak IP için iki Qwen çağrısı arasındaki minimum süre.
# (Payload / davranış kanıtı varsa bu cooldown bypass edilir.)
VALIDATOR_MIN_INTERVAL_PER_SOURCE = 30

SOURCE_WINDOW_SECONDS = 60
SOURCE_MAX_EVENTS = 2000

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# ----------------------------------------------------------
# Akış telemetrisi anomali eşikleri (kapı + cooldown bypass için)
# ----------------------------------------------------------
TELEMETRY_MIN_PACKETS = 20          # hız tabanlı kural için minimum paket
TELEMETRY_HIGH_PPS = 500            # paket/sn -> flood şüphesi
TELEMETRY_SYN_ONLY_MIN = 10         # ACK'siz SYN sayısı
TELEMETRY_SYN_ONLY_RATIO = 0.80     # TCP paketlerinin en az %80'i saf SYN
TELEMETRY_RST_MIN = 5
TELEMETRY_RST_RATIO = 0.30
TELEMETRY_EXFIL_MIN_BYTES = 1_000_000
TELEMETRY_EXFIL_RATIO = 10.0        # giden/gelen byte oranı

# ----------------------------------------------------------
# HTTP çıkarımı: standart dışı portlar (tshark "decode as")
# 8443 bilerek yok: genelde TLS'tir, anahtar olmadan çözülemez.
# ----------------------------------------------------------
HTTP_EXTRA_PORTS = [8765, 8080, 8000, 8008, 8081, 8888, 3000, 5000, 9000]

HTTP_DECODE_AS_PARAMS = []

for _http_port in HTTP_EXTRA_PORTS:
    HTTP_DECODE_AS_PARAMS.extend(
        ["-d", f"tcp.port=={_http_port},http"]
    )


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

def safe_filename(value):
    text = str(value).strip()

    text = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        text,
    )

    text = text.strip("._")

    return text or "unknown"


_alert_name_counter = itertools.count(1)


def create_alert_paths(
        decision,
        label,
        confidence,
):
    """
    Benzersiz (.pcap, .json) yol çifti üretir.
    Etiket '.' içerebildiği için with_suffix() KULLANILMAZ.
    """
    confidence_text = (
        f"{float(confidence):.4f}"
        .replace(".", "_")
    )

    prefix = (
        f"{safe_filename(decision)}_"
        f"{safe_filename(label)[:48]}_"
        f"{confidence_text}"
    )

    while True:
        unique = (
            f"{time.time_ns()}_"
            f"{next(_alert_name_counter):06d}_"
            f"{uuid.uuid4().hex[:8]}"
        )

        stem = f"{prefix}_{unique}"

        pcap_path = ALERTS_DIRECTORY / f"{stem}.pcap"
        json_path = ALERTS_DIRECTORY / f"{stem}.json"

        if not pcap_path.exists() and not json_path.exists():
            return pcap_path, json_path


# ==========================================================
# FLOW KEY
# ==========================================================

SIMULATED_ATTACKER_IP = "185.220.101.46"
SIMULATED_PORT_MIN = 44000
SIMULATED_PORT_MAX = 46000

SIMULATED_ATTACKER_RANGES = (
    (44000, 44300, "185.220.101.46"),  # Senaryo 1: SQL Injection
    (44300, 44600, "45.155.205.233"),  # Senaryo 2: XSS
    (44600, 44900, "91.240.118.172"),  # Senaryo 3: Path Traversal / LFI
    (44900, 45200, "193.32.162.159"),  # Senaryo 4: Command Injection / RCE
    (45200, 45500, "103.145.13.88"),   # Senaryo 5: HTTP Credential Brute Force
    (45500, 45750, "194.26.29.114"),   # Senaryo 6: API Parameter Enumeration (IDOR)
    (45750, 46000, "162.142.125.10"),  # Senaryo 7: Multi-Port TCP Service Scan
)


def _simulated_attacker_ip_for_port(port):
    p = int(port or 0)
    for lo, hi, ip in SIMULATED_ATTACKER_RANGES:
        if lo <= p < hi:
            return ip
    return SIMULATED_ATTACKER_IP


def _detect_local_server_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return "192.168.1.10"


LOCAL_SERVER_IP = _detect_local_server_ip()


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

        if sport == 11434 or dport == 11434:
            return None

        src_ip = str(packet.ip.src)
        dst_ip = str(packet.ip.dst)

        if src_ip == "127.0.0.1" or dst_ip == "127.0.0.1" or src_ip == dst_ip:
            if proto != 6:
                return None
            if SIMULATED_PORT_MIN <= sport < SIMULATED_PORT_MAX:
                src_ip = _simulated_attacker_ip_for_port(sport)
                dst_ip = LOCAL_SERVER_IP
            elif SIMULATED_PORT_MIN <= dport < SIMULATED_PORT_MAX:
                src_ip = LOCAL_SERVER_IP
                dst_ip = _simulated_attacker_ip_for_port(dport)
            else:
                # Tarayıcının kendi Dashboard (127.0.0.1:8765/api/alerts) sorgularını yakalama
                return None

        return (
            src_ip,
            dst_ip,
            sport,
            dport,
            proto,
        )

    except Exception:
        return None


def reverse_flow_key(flow_key):
    src_ip, dst_ip, src_port, dst_port, proto = flow_key

    return (
        dst_ip,
        src_ip,
        dst_port,
        src_port,
        proto,
    )


def canonical_flow_key(flow_key):
    """
    Forward ve reverse yönü aynı anahtara indirger.
    """
    normalized = (
        str(flow_key[0]),
        str(flow_key[1]),
        int(flow_key[2]),
        int(flow_key[3]),
        int(flow_key[4]),
    )

    return min(
        normalized,
        reverse_flow_key(normalized),
    )


def flow_packet_records(flow_data):
    """
    Capture'da saklanan ham paketleri [(zaman, bytes), ...] olarak verir.
    """
    packets = flow_data.get("packets") or []
    timestamps = flow_data.get("timestamps") or []
    fallback = flow_data.get("last_seen")

    records = []

    for index, raw_packet in enumerate(packets):
        if index < len(timestamps):
            timestamp = timestamps[index]
        else:
            timestamp = fallback

        records.append((timestamp, bytes(raw_packet)))

    return records


def sort_packet_records(records):
    return sorted(
        records,
        key=lambda item: (
            item[0] if item[0] is not None else 0.0
        ),
    )


def build_original_packet_map(flows_to_process):
    """
    Ham paketleri yönden bağımsız (canonical) flow anahtarına göre gruplar.
    """
    grouped = defaultdict(list)

    for flow_key, flow_data in flows_to_process:
        try:
            canonical = canonical_flow_key(flow_key)
        except Exception:
            continue

        grouped[canonical].extend(
            flow_packet_records(flow_data)
        )

    return {
        key: sort_packet_records(records)
        for key, records in grouped.items()
    }


def find_flow_packets(
        flow_key,
        original_packet_map,
        extractor_flows=None,
):
    if original_packet_map:
        try:
            packets = original_packet_map.get(
                canonical_flow_key(flow_key)
            )
        except Exception:
            packets = None

        if packets:
            return packets

    if extractor_flows is not None:
        for candidate in (
                flow_key,
                reverse_flow_key(flow_key),
        ):
            packets = extractor_flows.get(candidate)

            if packets is not None:
                return packets

    return None


# ==========================================================
# DECISION
# ==========================================================

def decide(label, confidence):
    normalized_label = str(label).strip().lower()

    if normalized_label == "benign":
        return "BENIGN"

    if confidence < REVIEW_THRESHOLD:
        return "LOW_CONFIDENCE"

    if confidence < ALERT_THRESHOLD:
        return "REVIEW"

    return "ALERT"


# ==========================================================
# PCAP EXPORT
# ==========================================================

def _raw_bytes_to_ether(raw_bytes):
    """
    en0 (Ethernet) ve lo0 (macOS BSD Loopback DLT_NULL 4-byte header)
    paketlerini ortak standart Ethernet + IP çerçevesine dönüştürür.
    Ayrıca tek cihazda (attack_test.py) yapılan simülasyon paketlerinin IP
    başlıklarını dış saldırgan (185.220.101.46) <-> yerel sunucu olarak yazar.
    """
    raw_b = bytes(raw_bytes)
    if (
        len(raw_b) >= 24
        and raw_b[:4] in (b"\x02\x00\x00\x00", b"\x00\x00\x00\x02")
        and (raw_b[4] >> 4) == 4
    ):
        ip_pkt = IP(raw_b[4:])
        if ip_pkt.haslayer(TCP) and (ip_pkt.src == "127.0.0.1" or ip_pkt.dst == "127.0.0.1" or ip_pkt.src == ip_pkt.dst):
            sport = int(ip_pkt[TCP].sport)
            dport = int(ip_pkt[TCP].dport)
            if SIMULATED_PORT_MIN <= sport < SIMULATED_PORT_MAX:
                ip_pkt.src = _simulated_attacker_ip_for_port(sport)
                ip_pkt.dst = LOCAL_SERVER_IP
                del ip_pkt.chksum
                del ip_pkt[TCP].chksum
            elif SIMULATED_PORT_MIN <= dport < SIMULATED_PORT_MAX:
                ip_pkt.src = LOCAL_SERVER_IP
                ip_pkt.dst = _simulated_attacker_ip_for_port(dport)
                del ip_pkt.chksum
                del ip_pkt[TCP].chksum
        return (
            Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02", type=0x0800)
            / ip_pkt
        )
    return Ether(raw_b)


def convert_to_scapy_packets(packets):
    scapy_packets = []

    for packet in packets:
        try:
            capture_time = None

            if (
                isinstance(packet, tuple)
                and len(packet) == 2
            ):
                capture_time, packet = packet

            if isinstance(
                    packet,
                    (bytes, bytearray)
            ):
                scapy_packet = _raw_bytes_to_ether(packet)

            elif hasattr(
                    packet,
                    "get_raw_packet"
            ):
                scapy_packet = _raw_bytes_to_ether(
                    packet.get_raw_packet()
                )

            elif hasattr(packet, "haslayer"):
                scapy_packet = packet.copy()

            else:
                continue

            if (
                PRESERVE_CAPTURE_TIMESTAMPS
                and capture_time is not None
            ):
                scapy_packet.time = float(
                    capture_time
                )

            scapy_packets.append(
                scapy_packet
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
        verbose=True,
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

    if verbose:
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


HTTP_BODY_PREVIEW_CHARS = 2048
HTTP_RAW_REQUEST_MAX_CHARS = 6000
HTTP_MAX_REQUESTS_IN_RAW = 5

_HEX_COLON = re.compile(r"^(?:[0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}$")
_RESPONSE_LINE = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)")


def _field_text(value):
    """PyShark JSON alanı str ya da list olabilir."""
    if value is None:
        return None

    if isinstance(value, (list, tuple)):
        value = "".join(str(item) for item in value)

    return str(value)


def _decode_body(value):
    text = _field_text(value)

    if not text:
        return None

    # tshark bazen file_data'yı "7b:22:61..." hex olarak verir.
    if _HEX_COLON.match(text.strip()):
        try:
            return bytes.fromhex(
                text.strip().replace(":", "")
            ).decode("utf-8", errors="replace")
        except ValueError:
            pass

    return text


def _header_lines(value):
    text = _field_text(value)

    if not text:
        return []

    text = text.replace("\\r\\n", "\n").replace("\r\n", "\n")

    return [line.strip() for line in text.split("\n") if line.strip()]


def _extract_http_response(http_layer):
    """
    http.response paketinden durum kodu / açıklama / Content-Length alır.
    Yanıt değilse None döner.
    """
    status_code = _field_text(getattr(http_layer, "response_code", None))
    reason = _field_text(
        getattr(http_layer, "response_code_desc", None)
        or getattr(http_layer, "response_phrase", None)
    )

    if not status_code:
        for line in _header_lines(
                getattr(http_layer, "response_line", None)
        ):
            match = _RESPONSE_LINE.search(line)

            if match:
                status_code = match.group(1)
                reason = reason or (match.group(2) or None)
                break

    if not status_code:
        return None

    status_code = str(status_code).strip()

    content_length = _field_text(
        getattr(http_layer, "content_length", None)
        or getattr(http_layer, "content_length_header", None)
    )

    return {
        "status_code": status_code,
        "reason": reason.strip() if reason else None,
        "content_length": content_length.strip() if content_length else None,
    }


def _format_response(response):
    if not response:
        return None

    text = f"{response['status_code']} {response.get('reason') or ''}".strip()

    if response.get("content_length"):
        text += f" (Content-Length: {response['content_length']})"

    return text


def _summarize_responses(responses):
    if not responses:
        return None

    counts = Counter(
        f"{item['status_code']} {item.get('reason') or ''}".strip()
        for item in responses
    )

    return "; ".join(
        f"{status} x{count}" if count > 1 else status
        for status, count in counts.items()
    )


def extract_http_request_from_pcap(pcap_file, extra_ports=None):
    """
    Düz metin HTTP isteklerini VE sunucu yanıtlarını çıkarır. LLM'in
    "zararsız API çağrısı mı, gerçek SQLi mi" ayrımını görebilmesi için
    TÜM header'ları, body'nin ilk kısmını ve sunucunun yanıt kodunu
    (401/403/404/500...) ham metin olarak döndürür.
    """
    pcap_path = Path(pcap_file)

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        return None

    http_capture = None

    # Akışın kendi portları da HTTP olarak çözülür: standart dışı bir
    # porttaki (örn. 7275) HTTP trafiği de payload kanıtına dönüşür.
    decode_params = list(HTTP_DECODE_AS_PARAMS)

    for extra_port in extra_ports or []:
        try:
            extra_port = int(extra_port)
        except (TypeError, ValueError):
            continue

        if extra_port in HTTP_EXTRA_PORTS or extra_port in (80, 443):
            continue

        decode_params.extend(["-d", f"tcp.port=={extra_port},http"])

    try:
        http_capture = pyshark.FileCapture(
            str(pcap_path),
            tshark_path=TSHARK_PATH,
            display_filter="http.request or http.response",
            custom_parameters=decode_params,
            keep_packets=False,
            use_json=False,
            eventloop=event_loop,
        )

        requests = []
        responses = []

        for packet in http_capture:
            if not hasattr(packet, "http"):
                continue

            http_layer = packet.http

            method = _field_text(getattr(http_layer, "request_method", None))
            response_code = _field_text(getattr(http_layer, "response_code", None))

            # Sunucu yanıtı (istek metodu yok veya response_code var -> yanıt paketidir)
            if response_code or not method:
                response = _extract_http_response(http_layer)

                if response is not None:
                    responses.append(response)
                continue

            uri = _field_text(
                getattr(http_layer, "request_uri", None)
                or getattr(http_layer, "request_full_uri", None)
            )
            version = _field_text(
                getattr(http_layer, "request_version", None)
            ) or "HTTP/1.1"

            lines = _header_lines(getattr(http_layer, "request_line", None))

            body = _decode_body(
                getattr(http_layer, "file_data", None)
                or getattr(http_layer, "request_body", None)
            )

            headers = {}

            for line in lines:
                if ":" in line:
                    name, _, value = line.partition(":")
                    headers[name.strip().lower()] = value.strip()

            path, query = None, None

            if uri:
                clean_uri = re.sub(r"^https?://[^/]+", "", uri) or "/"
                path, _, query = clean_uri.partition("?")
                query = query or None

            if any([method, path, query, body]):
                requests.append(
                    {
                        "method": method,
                        "uri": uri,
                        "version": version,
                        "path": path,
                        "query": query,
                        "body": body,
                        "headers": headers,
                        "header_lines": lines,
                        "response": None,
                    }
                )

        if not requests:
            return None

        # İstek/yanıt eşlemesi: yalnızca sayılar tutuyorsa sıra bazlı eşle
        # (kayıp paket / pipelining durumunda yanlış eşleşmeyi önler).
        responses_paired = len(responses) == len(requests)

        if responses_paired:
            for item, response in zip(requests, responses):
                item["response"] = response

        raw_parts = []

        for item in requests[:HTTP_MAX_REQUESTS_IN_RAW]:
            part = [f"{item['method'] or '?'} {item['uri'] or '/'} {item['version']}"]
            part.extend(item["header_lines"])

            if item["body"]:
                part.append("")
                part.append(item["body"][:HTTP_BODY_PREVIEW_CHARS])

            if item["response"]:
                part.append("")
                part.append(
                    "<< SERVER RESPONSE: "
                    + _format_response(item["response"])
                )

            raw_parts.append("\n".join(part))

        raw_request = "\n\n----\n\n".join(raw_parts)

        response_summary = _summarize_responses(responses)

        # Kırpmada yanıt bilgisi kaybolmasın diye özet en başa konur.
        if response_summary:
            raw_request = (
                f"# server_responses: {response_summary}\n\n" + raw_request
            )

        raw_request = raw_request[:HTTP_RAW_REQUEST_MAX_CHARS]

        combined_headers = {}

        for item in requests:
            combined_headers.update(item["headers"])

        bodies = [item["body"] for item in requests if item["body"]]
        paths = [item["path"] for item in requests if item["path"]]
        queries = [item["query"] for item in requests if item["query"]]
        methods = [item["method"] for item in requests if item["method"]]

        return {
            "method": methods[0] if methods else None,
            "path": "\n".join(paths) if paths else None,
            "query": "\n".join(queries) if queries else None,
            "body": "\n".join(bodies) if bodies else None,
            "headers": combined_headers,
            "request_count": len(requests),
            "raw_request": raw_request,
            "responses": responses,
            "response_codes": [item["status_code"] for item in responses],
            "response_summary": response_summary,
        }

    except Exception as exc:
        print("HTTP extraction failed ->", repr(exc))
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
        flow_ports=None,
        protocol=6,
):
    """
    HTTP kanıtı artık Layer 1 etiketinden BAĞIMSIZ çıkarılır (blind
    validation için: "web attack" demeyen ama HTTP içeren akışlarda da
    LLM payload'u görebilsin; ayrıca kanıtın varlığı etiketi sızdırmasın).
    Yalnızca TCP (protocol==6) akışlarında tshark HTTP dissector çalıştırılır;
    UDP akışlarında gereksiz tshark subprocess yükü engellenir.
    """
    if int(protocol or 0) == 6:
        evidence = extract_http_request_from_pcap(
            pcap_file,
            extra_ports=flow_ports,
        )
    else:
        evidence = None

    layer2_dict = None

    # HTTP kanıtı varsa Layer 1 etiketi ne olursa olsun ("Reconnaissance" dahil)
    # Layer 2 Payload sınıflandırıcıyı çalıştır; böylece SQLi/XSS kaçmaz!
    try:
        if evidence is not None:
            layer2_dict = layer2_classifier.classify_http_request(
                method=evidence["method"],
                path=evidence["path"],
                query=evidence["query"],
                body=evidence["body"],
                headers=evidence["headers"],
            ).to_dict()
        elif should_run_layer2(layer1_label):
            layer2_dict = layer2_classifier.classify(None).to_dict()
    except Exception as exc:
        print("LAYER2 classification warning ->", repr(exc))
        layer2_dict = None

    if evidence is None:
        return layer2_dict, None

    body = evidence.get("body")

    evidence_metadata = {
        "method": evidence["method"],
        "path": evidence["path"],
        "query": evidence["query"],
        "headers": evidence["headers"],
        "body_preview": body[:HTTP_BODY_PREVIEW_CHARS] if body else None,
        "raw_request": evidence["raw_request"],
        "has_query": bool(evidence["query"]),
        "has_body": bool(body),
        "request_count": evidence["request_count"],
        "has_response": bool(evidence.get("responses")),
        "responses": evidence.get("responses") or [],
        "response_codes": evidence.get("response_codes") or [],
        "response_summary": evidence.get("response_summary"),
    }

    return layer2_dict, evidence_metadata


# ==========================================================
# SOURCE ACTIVITY (kanıtı zenginleştirir)
# ==========================================================

source_activity = defaultdict(
    lambda: deque(maxlen=SOURCE_MAX_EVENTS)
)

source_http_activity = defaultdict(
    lambda: deque(maxlen=40)
)


def update_source_activity(flow_info, record=True):
    """
    Kaynak IP'nin son SOURCE_WINDOW_SECONDS içindeki davranışını özetler.
    """
    src_ip = flow_info["src_ip"]
    now = flow_info.get("timestamp") or time.time()

    events = source_activity[src_ip]

    if record:
        events.append(
            (
                now,
                flow_info["dst_ip"],
                flow_info["dst_port"],
                flow_info["protocol"],
            )
        )

    cutoff = now - SOURCE_WINDOW_SECONDS

    while events and events[0][0] < cutoff:
        events.popleft()

    # Brute force izi: aynı hedefe (ip:port) tekrar tekrar açılan akışlar.
    target_counts = Counter((e[1], e[2]) for e in events)
    top_target, top_target_flows = (
        target_counts.most_common(1)[0]
        if target_counts
        else (None, 0)
    )

    return {
        "window_seconds": SOURCE_WINDOW_SECONDS,
        "flow_count": len(events),
        "unique_dst_ips": len({e[1] for e in events}),
        "unique_dst_ports": len({e[2] for e in events}),
        "max_flows_to_single_target": top_target_flows,
        "top_target": (
            f"{top_target[0]}:{top_target[1]}" if top_target else None
        ),
    }


def update_source_http_activity(
        src_ip,
        http_evidence,
        activity,
        behavioral_findings,
):
    """
    Aynı kaynak IP'den gelen ardışık HTTP isteklerini (örn. /api/users?id=1, id=2, id=3
    veya /login denemeleri) akışlar arasında birleştirir; hem `activity` içine
    `recent_http_requests` ekler (Qwen tüm diziyi görsün diye) hem de parametre
    taraması / IDOR / brute-force varsa `behavioral_findings` listesine ekler.
    """
    if not isinstance(http_evidence, dict) or not http_evidence:
        return

    if _is_benign_dashboard_polling(http_evidence):
        return

    now = time.time()
    history = source_http_activity[src_ip]
    cutoff = now - SOURCE_WINDOW_SECONDS

    while history and history[0][0] < cutoff:
        history.popleft()

    method = str(http_evidence.get("method") or "GET").strip()
    raw_paths = [
        p.strip()
        for p in str(http_evidence.get("path") or "").splitlines()
        if p.strip()
    ]
    raw_queries = [
        q.strip()
        for q in str(http_evidence.get("query") or "").splitlines()
        if q.strip()
    ]
    norm_path = re.sub(r"^https?://[^/]+", "", raw_paths[0]) if raw_paths else "/"
    query_str = raw_queries[0] if raw_queries else ""
    body_str = str(http_evidence.get("body_preview") or "").strip()[:120]
    resp_codes = [str(c) for c in (http_evidence.get("response_codes") or [])]

    req_summary = f"{method} {norm_path}" + (f"?{query_str}" if query_str else "")
    if body_str:
        req_summary += f" [body: {body_str[:60]}]"
    if resp_codes:
        req_summary += f" -> HTTP {resp_codes[0]}"
    history.append((now, method, norm_path, query_str, req_summary, body_str, resp_codes))

    recent_list = [item[4] for item in history][-10:]
    if isinstance(activity, dict):
        activity["recent_http_requests"] = recent_list
        activity["http_request_count_in_window"] = len(history)

    # 1) HTTP Credential Brute Force (/login, /api/login, /auth vb. veya ardışık 401/403 yanıtları)
    is_auth_endpoint = any(
        tok in norm_path.lower()
        for tok in ("/login", "/signin", "/auth", "/session", "/token")
    )
    auth_attempts = [
        item for item in history
        if any(tok in item[2].lower() for tok in ("/login", "/signin", "/auth", "/session", "/token"))
        or ("401" in item[6])
    ]
    already_brute = any(
        isinstance(b, dict) and b.get("behavior") == "http_credential_brute_force"
        for b in (behavioral_findings or [])
    )
    if (is_auth_endpoint or "401" in resp_codes) and len(auth_attempts) >= 3 and not already_brute and isinstance(behavioral_findings, list):
        behavioral_findings.append(
            {
                "behavior": "http_credential_brute_force",
                "score": 40,
                "confidence": 0.94,
                "mitre": "T1110.001",
                "evidence": {
                    "endpoint": norm_path,
                    "attempt_count": len(auth_attempts),
                    "recent_attempts": [item[4] for item in auth_attempts[-8:]],
                },
            }
        )
        return

    # 2) Aynı endpoint'e farklı query parametreleriyle ardışık istekler (örn. id=1, id=2, id=3)
    same_path_queries = [
        item[3]
        for item in history
        if item[2] == norm_path and item[3]
    ]
    distinct_queries = list(dict.fromkeys(same_path_queries))

    already_flagged = any(
        isinstance(b, dict) and b.get("behavior") == "http_parameter_enumeration"
        for b in (behavioral_findings or [])
    )

    if len(distinct_queries) >= 2 and not already_flagged and isinstance(behavioral_findings, list):
        behavioral_findings.append(
            {
                "behavior": "http_parameter_enumeration",
                "score": 35,
                "confidence": 0.92,
                "mitre": "T1595.002",
                "evidence": {
                    "endpoint": norm_path,
                    "distinct_query_count": len(distinct_queries),
                    "observed_queries": distinct_queries[-8:],
                    "recent_requests": recent_list[-8:],
                },
            }
        )


def cleanup_source_activity():
    cutoff = time.time() - SOURCE_WINDOW_SECONDS

    for src_ip in list(source_activity.keys()):
        events = source_activity[src_ip]

        if not events or events[-1][0] < cutoff:
            del source_activity[src_ip]

    for src_ip in list(source_http_activity.keys()):
        events = source_http_activity[src_ip]

        if not events or events[-1][0] < cutoff:
            del source_http_activity[src_ip]


# ==========================================================
# FLOW TELEMETRY (NetFlow özeti)
# ==========================================================
# Layer 1'in ETİKETİ verilmez; yalnızca akışın fiziksel metrikleri
# (süre, hacim, hız, TCP bayrakları) ham paketlerden hesaplanır.
# Böylece LLM "45 paket 0.05 sn'de mi, 10 sn'de mi" ayrımını görebilir.

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20


def _telemetry_items(packets):
    """(zaman, scapy_paketi, boyut) üçlüleri üretir."""
    items = []

    for entry in packets or []:
        timestamp = None
        packet = entry

        if isinstance(entry, tuple) and len(entry) == 2:
            timestamp, packet = entry

        try:
            if isinstance(packet, (bytes, bytearray)):
                raw = bytes(packet)
                parsed = _raw_bytes_to_ether(raw)
                size = len(raw)

            elif hasattr(packet, "get_raw_packet"):
                raw = bytes(packet.get_raw_packet())
                parsed = _raw_bytes_to_ether(raw)
                size = len(raw)

            elif hasattr(packet, "haslayer"):
                parsed = packet
                size = len(packet)

            else:
                continue

        except Exception:
            continue

        if timestamp is None:
            try:
                timestamp = float(parsed.time)
            except Exception:
                timestamp = None

        items.append((timestamp, parsed, size))

    return items


def _l4_payload_length(ip_layer, l4_layer):
    """
    Ethernet padding'ini saymadan L4 payload uzunluğu.
    (Boş ACK paketleri 60 byte'a doldurulur; len(payload) yanıltır.)
    """
    try:
        ip_total = int(ip_layer.len or 0)

        if ip_total > 0:
            if l4_layer.haslayer(TCP):
                return max(
                    0,
                    ip_total
                    - int(ip_layer.ihl) * 4
                    - int(l4_layer[TCP].dataofs) * 4,
                )

            if l4_layer.haslayer(UDP):
                return max(0, int(l4_layer[UDP].len) - 8)

        return len(bytes(l4_layer.payload))

    except Exception:
        return 0


def compute_flow_telemetry(packets, flow_key):
    """
    Bir akışın ham paketlerinden NetFlow benzeri özet çıkarır.
    İleri yön = flow_key'deki src_ip:src_port.
    """
    src_ip, dst_ip, src_port, dst_port, proto = flow_key

    items = _telemetry_items(packets)

    if not items:
        return None

    fwd_packets = bwd_packets = 0
    fwd_bytes = bwd_bytes = 0
    fwd_payload = bwd_payload = 0

    tcp_packets = 0
    flags = {
        "syn_count": 0,        # saf SYN (ACK yok)
        "syn_ack_count": 0,
        "ack_count": 0,
        "psh_count": 0,
        "rst_count": 0,
        "fin_count": 0,
        "urg_count": 0,
    }

    timestamps = []

    for timestamp, parsed, size in items:
        if not parsed.haslayer(IP):
            continue

        ip_layer = parsed[IP]

        l4_layer = None
        sport = None

        if parsed.haslayer(TCP):
            l4_layer = parsed[TCP]
            sport = int(l4_layer.sport)
        elif parsed.haslayer(UDP):
            l4_layer = parsed[UDP]
            sport = int(l4_layer.sport)

        is_forward = (
            str(ip_layer.src) == str(src_ip)
            and (sport is None or sport == int(src_port))
        )

        payload_len = (
            _l4_payload_length(ip_layer, l4_layer)
            if l4_layer is not None
            else 0
        )

        if is_forward:
            fwd_packets += 1
            fwd_bytes += size
            fwd_payload += payload_len
        else:
            bwd_packets += 1
            bwd_bytes += size
            bwd_payload += payload_len

        if timestamp is not None:
            timestamps.append(float(timestamp))

        if parsed.haslayer(TCP):
            tcp_packets += 1
            flag_value = int(parsed[TCP].flags)

            has_syn = bool(flag_value & TCP_FLAG_SYN)
            has_ack = bool(flag_value & TCP_FLAG_ACK)

            if has_syn and has_ack:
                flags["syn_ack_count"] += 1
            elif has_syn:
                flags["syn_count"] += 1

            if has_ack:
                flags["ack_count"] += 1
            if flag_value & TCP_FLAG_PSH:
                flags["psh_count"] += 1
            if flag_value & TCP_FLAG_RST:
                flags["rst_count"] += 1
            if flag_value & TCP_FLAG_FIN:
                flags["fin_count"] += 1
            if flag_value & TCP_FLAG_URG:
                flags["urg_count"] += 1

    total_packets = fwd_packets + bwd_packets

    if total_packets == 0:
        return None

    total_bytes = fwd_bytes + bwd_bytes

    duration = 0.0

    if len(timestamps) >= 2:
        duration = max(timestamps) - min(timestamps)

    packets_per_second = None
    bytes_per_second = None

    if duration > 0:
        packets_per_second = round(total_packets / duration, 2)
        bytes_per_second = round(total_bytes / duration, 2)

    byte_ratio = None

    if bwd_bytes > 0:
        byte_ratio = round(fwd_bytes / bwd_bytes, 2)

    return {
        "flow_duration_seconds": round(duration, 4),
        "total_packets": total_packets,
        "fwd_packets": fwd_packets,
        "bwd_packets": bwd_packets,
        "total_fwd_bytes": fwd_bytes,
        "total_bwd_bytes": bwd_bytes,
        "fwd_payload_bytes": fwd_payload,
        "bwd_payload_bytes": bwd_payload,
        "fwd_bwd_byte_ratio": byte_ratio,
        "avg_packet_size": round(total_bytes / total_packets, 1),
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "tcp_packets": tcp_packets,
        "tcp_flags": flags,
    }


def telemetry_anomaly_reason(telemetry):
    """
    Telemetride açık bir flood / tarama / sızıntı izi var mı?
    Yoksa None. (Yalnızca kapı ve cooldown bypass kararında kullanılır;
    LLM'e ipucu olarak verilmez, böylece doğrulama kör kalır.)
    """
    if not isinstance(telemetry, dict):
        return None

    total_packets = int(telemetry.get("total_packets") or 0)
    pps = telemetry.get("packets_per_second")
    tcp_packets = int(telemetry.get("tcp_packets") or 0)
    flags = telemetry.get("tcp_flags") or {}

    if (
        pps
        and total_packets >= TELEMETRY_MIN_PACKETS
        and float(pps) >= TELEMETRY_HIGH_PPS
    ):
        return "high_packet_rate"

    syn_count = int(flags.get("syn_count") or 0)

    if (
        tcp_packets
        and syn_count >= TELEMETRY_SYN_ONLY_MIN
        and syn_count / tcp_packets >= TELEMETRY_SYN_ONLY_RATIO
    ):
        return "syn_without_handshake"

    rst_count = int(flags.get("rst_count") or 0)

    if (
        tcp_packets
        and rst_count >= TELEMETRY_RST_MIN
        and rst_count / tcp_packets >= TELEMETRY_RST_RATIO
    ):
        return "reset_heavy"

    fwd_bytes = int(telemetry.get("total_fwd_bytes") or 0)
    bwd_bytes = int(telemetry.get("total_bwd_bytes") or 0)

    if fwd_bytes >= TELEMETRY_EXFIL_MIN_BYTES and (
        bwd_bytes == 0
        or fwd_bytes / max(bwd_bytes, 1) >= TELEMETRY_EXFIL_RATIO
    ):
        return "asymmetric_upload"

    return None


def _context_mentions_telemetry(context):
    if isinstance(context, dict):
        return "flow_telemetry" in context

    if isinstance(context, str):
        return "telemetry" in context.lower()

    return True  # bilinmeyen tür: dokunma


def build_validation_context_with_telemetry(
        flow_telemetry=None,
        **context_kwargs,
):
    """
    build_validation_context'e telemetriyi güvenli şekilde ekler:
      - fonksiyon `flow_telemetry` parametresini kabul ediyorsa ona verir,
      - kabul etmiyorsa (veya sessizce yok sayıyorsa) çıktıya kendisi ekler.
    Mevcut çağrı davranışı bozulmaz.
    """
    if not flow_telemetry:
        return build_validation_context(**context_kwargs)

    try:
        parameters = inspect.signature(
            build_validation_context
        ).parameters
    except (TypeError, ValueError):
        parameters = {}

    accepts_telemetry = "flow_telemetry" in parameters

    if accepts_telemetry:
        context = build_validation_context(
            flow_telemetry=flow_telemetry,
            **context_kwargs,
        )
    else:
        context = build_validation_context(**context_kwargs)

    if _context_mentions_telemetry(context):
        return context

    if isinstance(context, dict):
        context["flow_telemetry"] = flow_telemetry

    elif isinstance(context, str):
        context += (
            "\n\nFLOW TELEMETRY (physical flow metrics):\n"
            + json.dumps(
                safe_json_value(flow_telemetry),
                indent=2,
                ensure_ascii=False,
            )
        )

    return context


# ==========================================================
# VALIDATOR GATE + CACHE
# ==========================================================

assessment_cache = {}               # signature -> (stored_at, (validation, mitre))
validator_last_run_by_source = {}   # src_ip -> (monotonic_time, (validation, mitre))

LAYER2_NON_ATTACK_LABELS = {
    "",
    "none",
    "unknown",
    "unknown_web_attack",
    "benign",
    "normal",
    "uncertain",
    "abstain",
}


def _skipped_validation(status, reason, message):
    """Qwen çağrılmadı. status: skipped | pending_user."""
    return {
        "status": status,
        "reason": reason,
        "message": message,
        "verdict": None,
        "confidence": 0.0,
        "model": VALIDATOR_MODEL,
        "timing": {"seconds": 0.0},
    }


def has_layer2_attack_evidence(layer2_result):
    if not isinstance(layer2_result, dict):
        return False

    status = str(layer2_result.get("status") or "").strip().lower()
    if status != "classified":
        return False

    label = normalize_layer2_label(
        layer2_result.get("label") or ""
    )

    return label not in LAYER2_NON_ATTACK_LABELS


LOCAL_NOISE_UDP_PORTS = {53, 67, 68, 123, 137, 138, 1900, 5353, 5355}


def _is_multicast_or_local_noise(flow_info):
    """
    SSDP (239.255.255.250:1900), mDNS (224.0.0.251:5353), Broadcast
    (255.255.255.255), Link-Local (169.254.x.x) ve rutin UDP yerel keşif
    paketlerinin Qwen kuyruğunu şişirmesini engeller.
    """
    if not isinstance(flow_info, dict):
        return False

    for key in ("src_ip", "dst_ip"):
        ip_text = str(flow_info.get(key) or "").strip()
        if not ip_text:
            continue
        if ip_text == "255.255.255.255" or ip_text.endswith(".255"):
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_text)
            if (
                ip_obj.is_multicast
                or ip_obj.is_link_local
                or ip_obj.is_unspecified
            ):
                return True
        except ValueError:
            pass

    proto = int(flow_info.get("protocol") or 0)
    src_port = int(flow_info.get("src_port") or 0)
    dst_port = int(flow_info.get("dst_port") or 0)

    if proto == 17 and (
        src_port in LOCAL_NOISE_UDP_PORTS
        or dst_port in LOCAL_NOISE_UDP_PORTS
    ):
        return True

    return False


def _is_routine_encrypted_port_443(flow_info):
    """
    Port 443 (TLS/HTTPS veya QUIC) trafiğinde açık metin HTTP payload'u yoktur.
    Davranışsal anomali (tarama/flood) veya telemetri anomalisi yoksa rutin
    arka plan HTTPS trafiğinin Qwen kuyruğunu tıkamasını önler.
    """
    if not isinstance(flow_info, dict):
        return False

    src_port = int(flow_info.get("src_port") or 0)
    dst_port = int(flow_info.get("dst_port") or 0)

    return src_port == 443 or dst_port == 443


DASHBOARD_API_PATHS = {
    "/",
    "/index.html",
    "/dashboard.html",
    "/favicon.ico",
    "/api/health",
    "/api/alerts",
    "/api/stats",
    "/api/matrix",
    "/api/mappings",
    "/api/navigator",
    "/api/stream",
}


def _is_benign_dashboard_polling(http_evidence):
    """
    Dashboard'un kendi rutin API sorgularının (örn. /api/alerts?limit=500)
    has_query=True yüzünden saldırı sanılıp Qwen kuyruğuna girmesini önler.
    """
    if not isinstance(http_evidence, dict):
        return False

    paths = [
        p.strip()
        for p in str(http_evidence.get("path") or "").splitlines()
        if p.strip()
    ]
    if not paths:
        return False

    for p in paths:
        norm_p = re.sub(r"^https?://[^/]+", "", p) or "/"
        if norm_p not in DASHBOARD_API_PATHS and not norm_p.startswith("/api/alerts/") and not norm_p.startswith("/api/technique/"):
            return False

    query = str(http_evidence.get("query") or "").strip()
    if query and not re.fullmatch(r"(limit=\d+|force=[01]|[\s&])+", query):
        return False

    return not bool(http_evidence.get("has_body"))


def should_run_validator(
        confidence,
        behavioral_findings,
        correlation_data,
        layer2_result,
        layer1_label=None,
        flow_telemetry=None,
        flow_info=None,
        http_evidence=None,
):
    """
    Kanıt kapısı: Qwen'e "gerçekten saldırı mı?" diye sormaya değer mi?
    1) Gerçek HTTP payload / Layer 2 saldırı / Davranışsal anomali / Telemetri
       anomalisi varsa doğrudan geçirir.
    2) Multicast/Broadcast (SSDP, mDNS vb.) ve davranış/telemetri anomalisi
       olmayan şifreli 443 (HTTPS/QUIC) gürültüsünü filtreler.
    3) Correlation engine her >=0.50 akışa otomatik 'medium' ve risk>=50
       verdiği için, tek başına 'medium' korelasyonun kapıyı delmesi engellenir.
    """
    if has_layer2_attack_evidence(layer2_result):
        return True, "layer2_attack"

    http_evidence = http_evidence or {}
    if _is_benign_dashboard_polling(http_evidence) and not behavioral_findings:
        return False, "benign_dashboard_ui_polling"

    if http_evidence.get("has_query") or http_evidence.get("has_body"):
        return True, "http_payload_evidence"

    if behavioral_findings:
        return True, "behavioral_findings"

    telemetry_reason = telemetry_anomaly_reason(flow_telemetry)
    if telemetry_reason:
        return True, f"flow_telemetry={telemetry_reason}"

    if _is_multicast_or_local_noise(flow_info):
        return False, "multicast_or_local_discovery_noise"

    has_plaintext_http = bool(http_evidence.get("request_count"))

    if _is_routine_encrypted_port_443(flow_info) and not has_plaintext_http:
        return False, "encrypted_port_443_without_behavior_or_payload"

    if has_plaintext_http and confidence >= REVIEW_THRESHOLD:
        return True, "plaintext_http_request"

    if confidence < REVIEW_THRESHOLD:
        return False, "below_review_threshold_and_no_supporting_evidence"

    is_benign_label = (
        str(layer1_label).strip().lower() == "benign"
    )

    if (
        confidence >= VALIDATOR_MIN_CONFIDENCE
        and not is_benign_label
    ):
        return True, "high_layer1_confidence"

    return False, "low_confidence_and_no_supporting_evidence"


def _bucket(value):
    # 1,2,3,4-7,8-15,... -> tarama büyüdükçe imza değişir.
    return int(value).bit_length()


def _short_hash(value):
    """Payload parmak izi (kısa MD5). Boş değer -> None."""
    if value is None:
        return None

    text = str(value)

    if not text:
        return None

    try:
        digest = hashlib.md5(
            text.encode("utf-8", errors="replace"),
            usedforsecurity=False,
        )
    except TypeError:
        digest = hashlib.md5(text.encode("utf-8", errors="replace"))

    return digest.hexdigest()[:12]


def telemetry_signature(telemetry):
    """
    Telemetrinin kaba (bucket'lı) parmak izi: SYN-flood ile normal oturum
    aynı imzayı paylaşmasın, ama küçük sapmalar cache'i bozmasın.
    """
    if not isinstance(telemetry, dict):
        return None

    flags = telemetry.get("tcp_flags") or {}
    pps = telemetry.get("packets_per_second") or 0
    total_bytes = (
        int(telemetry.get("total_fwd_bytes") or 0)
        + int(telemetry.get("total_bwd_bytes") or 0)
    )

    return (
        _bucket(telemetry.get("total_packets") or 0),
        _bucket(int(pps)),
        _bucket(total_bytes >> 10),
        bool(flags.get("syn_count")),
        bool(flags.get("rst_count")),
        bool(flags.get("psh_count")),
        bool(flags.get("fin_count")),
        bool(telemetry.get("total_bwd_bytes")),
    )


def build_assessment_signature(
        label,
        flow_info,
        behavioral_findings,
        correlation_data,
        layer2_result,
        http_evidence,
        activity,
        flow_telemetry=None,
):
    """
    Kanıt imzası. Confidence değerleri bilerek imzada YOKTUR.
    dst_port eklendi: validator servis bağlamına (SSDP, OSPF, DNS...)
    bakar; farklı servis = farklı kanıt.
    Payload'a duyarlı: query/body hash'i ve sunucu yanıt kodları imzadadır;
    aynı endpoint'e yapılan zararsız istek ile SQLi isteği artık aynı imzayı
    paylaşmaz.
    """
    behaviors = tuple(
        sorted(
            {
                str(item.get("behavior"))
                for item in behavioral_findings or []
                if isinstance(item, dict)
            }
        )
    )

    layer2_result = layer2_result or {}
    http_evidence = http_evidence or {}
    activity = activity or {}

    raw_paths = [
        p.strip()
        for p in str(http_evidence.get("path") or "").splitlines()
        if p.strip()
    ]
    norm_path = re.sub(r"^https?://[^/]+", "", raw_paths[0]) if raw_paths else None

    # Eğer Layer 2 açık bir exploit (SQLi/XSS/Traversal) bulmadıysa ama HTTP
    # akışı veya parametre taraması (http_parameter_enumeration) varsa, id=1..100
    # gibi 100 farklı query parametresinin 100 ayrı imza üretip kuyruğu şişirmesini önle:
    if http_evidence and not has_layer2_attack_evidence(layer2_result):
        return (
            "http_flow_non_layer2",
            flow_info.get("src_ip"),
            flow_info.get("dst_port"),
            flow_info.get("protocol"),
            behaviors,
            http_evidence.get("method"),
            norm_path,
            _short_hash(http_evidence.get("body_preview")),
        )

    response_codes = tuple(
        sorted(
            str(code)
            for code in (http_evidence.get("response_codes") or [])
        )
    )

    return (
        str(label).strip().lower(),
        flow_info.get("src_ip"),
        flow_info.get("dst_port"),
        flow_info.get("protocol"),
        behaviors,
        str(correlation_data.get("severity", "informational")).lower(),
        normalize_layer2_label(layer2_result.get("label") or ""),
        http_evidence.get("method"),
        norm_path,
        _short_hash(http_evidence.get("query")),
        _short_hash(http_evidence.get("body_preview")),
        response_codes,
        _bucket(activity.get("unique_dst_ports", 0)),
        _bucket(activity.get("unique_dst_ips", 0)),
        _bucket(activity.get("max_flows_to_single_target", 0)),
        telemetry_signature(flow_telemetry),
    )


def should_bypass_cooldown(
        last_validation,
        layer2_result,
        behavioral_findings,
        correlation_data,
        http_evidence,
        flow_telemetry,
):
    """
    Kaynak cooldown'u kötüye kullanılamasın: saldırgan ilk pakette masum bir
    istek atıp kendini 30 sn "Benign" olarak beyaz listeye aldıramaz.

    Bypass eder, eğer:
      - yeni akışta Layer 2 saldırı kanıtı varsa, VEYA
      - önceki karar saldırı değilken yeni akışta davranış / korelasyon /
        HTTP payload / telemetri anomalisi varsa.
    """
    if has_layer2_attack_evidence(layer2_result):
        return True, "layer2_attack_evidence"

    if behavioral_findings:
        return True, "behavioral_findings"

    previously_attack = False

    if isinstance(last_validation, dict) and (
        last_validation.get("status") == "completed"
    ):
        try:
            previously_attack = bool(
                is_attack_verdict(
                    last_validation,
                    SUSPICIOUS_MITRE_MIN_CONFIDENCE,
                )
            )
        except Exception:
            previously_attack = False

    if previously_attack:
        return False, None

    http_evidence = http_evidence or {}

    if http_evidence.get("has_query") or http_evidence.get("has_body"):
        return True, "http_payload_after_non_attack"

    telemetry_reason = telemetry_anomaly_reason(flow_telemetry)

    if telemetry_reason:
        return True, f"telemetry_{telemetry_reason}_after_non_attack"

    return False, None


def _cache_get(signature):
    entry = assessment_cache.get(signature)

    if entry is None:
        return None

    stored_at, value = entry
    age = time.monotonic() - stored_at

    if age > ASSESSMENT_CACHE_TTL:
        del assessment_cache[signature]
        return None

    return value, age


def _cache_put(signature, value):
    validation, _ = value

    if validation.get("status") != "completed":
        return  # error / invalid_response cache'lenmez

    if len(assessment_cache) >= ASSESSMENT_CACHE_MAX_ENTRIES:
        oldest = min(
            assessment_cache,
            key=lambda key: assessment_cache[key][0],
        )
        del assessment_cache[oldest]

    assessment_cache[signature] = (
        time.monotonic(),
        copy.deepcopy(value),
    )


def _reuse(value, reason, age):
    validation, mitre = copy.deepcopy(value)

    marker = {
        "reason": reason,
        "age_seconds": round(age, 2),
    }

    validation["reused"] = {**marker, "original_status": validation.get("status")}
    validation["timing"] = {"seconds": 0.0}
    validation.pop("raw_response", None)
    validation.pop("ollama_metrics", None)

    if isinstance(mitre, dict):
        mitre["reused"] = {**marker, "original_status": mitre.get("status")}
        mitre["timing"] = {
            "retrieval_seconds": 0.0,
            "qwen_seconds": 0.0,
            "total_seconds": 0.0,
        }
        mitre.pop("raw_output", None)
        mitre.pop("ollama_metrics", None)

    return validation, mitre


def decide_mitre_after_validation(
        validation,
        layer1_label,
        layer1_confidence,
        behavioral_findings,
        correlation_data,
        flow_info,
        layer2_result,
        http_evidence,
        activity,
):
    """Validator kararından sonra MITRE'nin ne yapacağını belirler."""
    if MITRE_MODE == "off":
        return skipped_mitre(
            "skipped",
            "mitre_disabled",
            "MITRE disabled (MITRE_MODE=off).",
        )

    if validation.get("status") != "completed":
        return skipped_mitre(
            "skipped",
            "validation_not_completed",
            "MITRE not run: threat validation did not complete.",
        )

    if not is_attack_verdict(validation, SUSPICIOUS_MITRE_MIN_CONFIDENCE):
        return skipped_mitre(
            "skipped",
            "verdict_not_attack",
            f"MITRE not needed: validator verdict="
            f"{validation.get('verdict')} "
            f"({float(validation.get('confidence') or 0) * 100:.0f}%).",
        )

    if MITRE_MODE == "on_demand":
        return skipped_mitre(
            "deferred",
            "awaiting_user_request",
            "Attack confirmed. Use 'MITRE Eşle' on the dashboard.",
        )

    return run_mitre_analysis(
        layer1_label=layer1_label,
        layer1_confidence=layer1_confidence,
        behavioral_findings=behavioral_findings,
        correlation_data=correlation_data,
        flow_info=flow_info,
        layer2_result=layer2_result,
        http_evidence=http_evidence,
        activity=activity,
        validation=validation,
        debug=MITRE_DEBUG,
    )


def get_threat_assessment(
        validation_context,
        layer1_label,
        layer1_confidence,
        behavioral_findings,
        correlation_data,
        flow_info,
        layer2_result,
        http_evidence,
        activity,
        flow_telemetry=None,
):
    """
    kanıt kapısı -> imza cache'i -> kaynak cooldown'u
    -> Qwen Threat Validator -> (gerekirse) MITRE

    Dönüş: (threat_validation, mitre_analysis)
    """
    if VALIDATOR_MODE == "off":
        return (
            _skipped_validation("skipped", "validator_disabled", "VALIDATOR_MODE=off."),
            skipped_mitre("skipped", "validation_not_run", "Validator disabled."),
        )

    # 1) Kanıt kapısı
    allowed, reason = should_run_validator(
        layer1_confidence,
        behavioral_findings,
        correlation_data,
        layer2_result,
        layer1_label=layer1_label,
        flow_telemetry=flow_telemetry,
        flow_info=flow_info,
        http_evidence=http_evidence,
    )

    if not allowed:
        return (
            _skipped_validation(
                "skipped",
                "low_evidence",
                f"Qwen not called: {reason} (confidence={layer1_confidence:.4f}).",
            ),
            skipped_mitre("skipped", "validation_not_run", "No validation, no MITRE."),
        )

    # 2) On-demand: Qwen'i dashboard butonu çağıracak
    if VALIDATOR_MODE == "on_demand":
        return (
            _skipped_validation(
                "pending_user",
                "on_demand",
                f"Evidence gate passed ({reason}). Use 'AI'a Sor' on the dashboard.",
            ),
            skipped_mitre("skipped", "validation_not_run", "Waiting for validation."),
        )

    # 3) İmza cache'i (payload + telemetri duyarlı)
    signature = build_assessment_signature(
        layer1_label,
        flow_info,
        behavioral_findings,
        correlation_data,
        layer2_result,
        http_evidence,
        activity,
        flow_telemetry=flow_telemetry,
    )

    cached = _cache_get(signature)

    if cached is not None:
        value, age = cached
        return _reuse(value, "same_evidence_signature", age)

    # 4) Kaynak başına cooldown (kanıt varsa bypass edilir)
    src_ip = flow_info.get("src_ip")
    last = validator_last_run_by_source.get(src_ip)
    now = time.monotonic()
    cooldown_bypass_reason = None

    if last is not None:
        last_time, last_value = last
        age = now - last_time

        if age < VALIDATOR_MIN_INTERVAL_PER_SOURCE:
            bypass, bypass_reason = should_bypass_cooldown(
                last_value[0],
                layer2_result,
                behavioral_findings,
                correlation_data,
                http_evidence,
                flow_telemetry,
            )

            if bypass:
                cooldown_bypass_reason = bypass_reason

                print(
                    "COOLDOWN BYPASS ->",
                    f"{src_ip}",
                    f"reason={bypass_reason}",
                    f"(age={age:.1f}s)",
                )

            elif last_value[0].get("status") == "completed":
                return _reuse(last_value, "source_cooldown", age)

            else:
                return (
                    _skipped_validation(
                        "skipped",
                        "cooldown",
                        f"Qwen not called: cooldown for {src_ip} "
                        f"({age:.1f}s < {VALIDATOR_MIN_INTERVAL_PER_SOURCE}s).",
                    ),
                    skipped_mitre("skipped", "validation_not_run", "Cooldown."),
                )

    # 5) Gerçek Qwen çağrısı: "gerçekten saldırı mı?"
    validation = validate_threat(validation_context)

    if cooldown_bypass_reason and isinstance(validation, dict):
        validation["cooldown_bypass"] = cooldown_bypass_reason

    # 6) MITRE yalnızca doğrulanmış saldırıda
    mitre_analysis = decide_mitre_after_validation(
        validation,
        layer1_label,
        layer1_confidence,
        behavioral_findings,
        correlation_data,
        flow_info,
        layer2_result,
        http_evidence,
        activity,
    )

    value = (validation, mitre_analysis)

    validator_last_run_by_source[src_ip] = (
        time.monotonic(),
        copy.deepcopy(value),
    )

    _cache_put(signature, value)

    return value


# ==========================================================
# CONSOLE OUTPUT
# ==========================================================

def print_threat_validation(validation):
    status = validation.get("status", "unknown")

    if status != "completed":
        print(
            "VALIDATOR ->",
            f"status={status}",
            f"reason={validation.get('reason')}",
        )

        if validation.get("message"):
            print("VALIDATOR MESSAGE ->", validation["message"])

        if validation.get("error"):
            print("VALIDATOR ERROR ->", validation["error"])

        return

    print(
        "VALIDATOR ->",
        f"verdict={validation.get('verdict')}",
        f"confidence={float(validation.get('confidence') or 0) * 100:.0f}%",
        f"time={float((validation.get('timing') or {}).get('seconds', 0.0)):.2f}s",
    )

    if validation.get("reused"):
        print("VALIDATOR REUSED ->", validation["reused"])

    if validation.get("cooldown_bypass"):
        print("VALIDATOR COOLDOWN BYPASS ->", validation["cooldown_bypass"])

    if validation.get("reasoning"):
        print("VALIDATOR REASONING ->", validation["reasoning"])

    if validation.get("benign_explanation"):
        print("VALIDATOR BENIGN EXPLANATION ->", validation["benign_explanation"])

    if validation.get("malicious_indicators"):
        print("VALIDATOR INDICATORS ->", validation["malicious_indicators"])

    if validation.get("recommended_next_step"):
        print("VALIDATOR NEXT STEP ->", validation["recommended_next_step"])


def print_mitre_analysis(mitre_analysis):
    if mitre_analysis is None:
        print("MITRE -> status=not_run")
        return

    status = mitre_analysis.get("status", "unknown")
    techniques = (mitre_analysis.get("result") or {}).get("techniques", [])
    candidates = mitre_analysis.get("candidates", [])

    print(
        "MITRE ->",
        f"status={status}",
        f"candidates={len(candidates)}",
        f"techniques={len(techniques)}",
    )

    if mitre_analysis.get("reason"):
        print("MITRE REASON ->", mitre_analysis["reason"])

    if mitre_analysis.get("message"):
        print("MITRE MESSAGE ->", mitre_analysis["message"])

    if mitre_analysis.get("error"):
        print("MITRE ERROR ->", mitre_analysis["error"])

    network_filter = mitre_analysis.get("network_observable_filter")

    if network_filter and network_filter.get("removed"):
        print("MITRE HOST-ONLY REMOVED ->", network_filter["removed"])

    for technique in techniques:
        print(
            "MITRE TECHNIQUE ->",
            technique.get("id", "UNKNOWN"),
            technique.get("name", ""),
            f"[{technique.get('visibility', '?')}]",
            "confidence=",
            technique.get("confidence", 0.0),
            "reason=",
            technique.get("reason", ""),
        )

    timing = mitre_analysis.get("timing") or {}

    if timing and status in ("completed", "insufficient_evidence", "error"):
        print(
            "MITRE TIMING ->",
            f"retrieval={timing.get('retrieval_seconds', 0.0):.4f}s",
            f"qwen={timing.get('qwen_seconds', 0.0):.4f}s",
            f"total={timing.get('total_seconds', 0.0):.4f}s",
        )


def print_action_response(action_response):
    if not isinstance(action_response, dict):
        return

    status = action_response.get("status", "not_run")
    actions = action_response.get("executed_actions") or []

    print(
        "ACTION AGENT ->",
        f"status={status}",
        f"mitigation={action_response.get('mitre_mitigation_id') or '-'}",
        f"actions={len(actions)}",
    )

    if action_response.get("action_plan_summary"):
        print("ACTION PLAN ->", action_response["action_plan_summary"])

    for item in actions:
        if isinstance(item, dict):
            print(
                "  [SOAR TOOL] ->",
                item.get("tool"),
                f"status={item.get('status')}",
                f"mode={item.get('execution_mode', '-')}",
                f"reason={item.get('reason', '')}",
            )


def decide_action_after_mitre(metadata):
    """Doğrulanmış saldırıda Action Agent'ı (otomatik veya on_demand) çalıştırır."""
    if ACTION_MODE == "off":
        return skipped_action(
            "skipped",
            "action_disabled",
            "Action Agent disabled (ACTION_MODE=off).",
        )

    validation = metadata.get("threat_validation") or {}

    if validation.get("status") != "completed":
        return skipped_action(
            "skipped",
            "validation_not_completed",
            "Action Agent waiting for threat validation.",
        )

    if not is_attack_verdict(validation, SUSPICIOUS_MITRE_MIN_CONFIDENCE):
        return skipped_action(
            "skipped",
            "verdict_not_attack",
            f"No action needed: verdict={validation.get('verdict')}.",
        )

    if ACTION_MODE == "on_demand":
        return skipped_action(
            "deferred",
            "awaiting_user_request",
            "Attack confirmed. Use 'Aksiyon Al' on the dashboard.",
        )

    return run_action_agent(metadata)


# ==========================================================
# ASYNC LLM & SOAR WORKER QUEUE (Zero Packet-Drop Buffer)
# ==========================================================

_llm_task_queue = queue.Queue(maxsize=32)
_llm_worker_started = False
_llm_worker_lock = threading.Lock()
_pending_signatures = set()
_recent_http_endpoint_alerts = {}  # (src_ip, dst_port, norm_path, has_enum) -> (monotonic_ts, metadata_file)
HTTP_BURST_CONSOLIDATION_SECONDS = 30.0


def _refresh_http_burst_evidence_in_metadata(metadata, llm_flow_info):
    """
    Kuyrukta bekleyen bir HTTP/Enumeration uyarısı sıra kendisine geldiğinde,
    o sırada gelen tüm ardışık istekleri (örn. id=1..100) `source_http_activity`
    üzerinden güncelleyerek Qwen'e tek seferde tam resmi sunar.
    """
    orig_src_ip = metadata.get("src_ip")
    http_ev = metadata.get("http_evidence")
    if not orig_src_ip or not isinstance(http_ev, dict):
        return

    history = list(source_http_activity.get(orig_src_ip) or [])
    if not history:
        return

    raw_paths = [
        p.strip()
        for p in str(http_ev.get("path") or "").splitlines()
        if p.strip()
    ]
    norm_path = re.sub(r"^https?://[^/]+", "", raw_paths[0]) if raw_paths else "/"
    recent_list = [item[4] for item in history][-15:]

    activity = metadata.get("source_activity")
    if not isinstance(activity, dict):
        activity = {}
        metadata["source_activity"] = activity

    activity["recent_http_requests"] = recent_list
    activity["http_request_count_in_window"] = len(history)

    same_path_queries = [
        item[3] for item in history if item[2] == norm_path and item[3]
    ]
    distinct_queries = list(dict.fromkeys(same_path_queries))

    behavioral_findings = metadata.get("behavioral_findings")
    if not isinstance(behavioral_findings, list):
        behavioral_findings = []
        metadata["behavioral_findings"] = behavioral_findings

    if len(distinct_queries) >= 2:
        updated = False
        for b in behavioral_findings:
            if isinstance(b, dict) and b.get("behavior") == "http_parameter_enumeration":
                b["evidence"] = {
                    "endpoint": norm_path,
                    "distinct_query_count": len(distinct_queries),
                    "observed_queries": distinct_queries[-12:],
                    "recent_requests": recent_list[-12:],
                }
                updated = True
                break
        if not updated:
            behavioral_findings.append(
                {
                    "behavior": "http_parameter_enumeration",
                    "score": 35,
                    "confidence": 0.92,
                    "mitre": "T1595.002",
                    "evidence": {
                        "endpoint": norm_path,
                        "distinct_query_count": len(distinct_queries),
                        "observed_queries": distinct_queries[-12:],
                        "recent_requests": recent_list[-12:],
                    },
                }
            )

    metadata["validation_context"] = build_validation_context_with_telemetry(
        flow_telemetry=metadata.get("flow_telemetry"),
        flow_info=llm_flow_info,
        behavioral_findings=behavioral_findings,
        http_evidence=http_ev,
        activity=activity,
        packet_count=metadata.get("packet_count", 0),
    )


def _llm_worker_loop():
    """
    Arka planda çalışan tekil Worker Thread.
    Paket yakalama döngüsünü (tshark) hiç bloklamadan sırayla:
      1) Qwen Threat Validator
      2) MITRE ATT&CK Mapper
      3) Qwen SOAR Action Agent
    adımlarını yürütür ve alert JSON dosyasını atomik olarak günceller.
    """
    while True:
        task = _llm_task_queue.get()
        if task is None:
            _llm_task_queue.task_done()
            break

        sig = task.get("signature")

        try:
            metadata_file = task["metadata_file"]
            metadata = task["metadata"]
            llm_flow_info = task["llm_flow_info"]

            _refresh_http_burst_evidence_in_metadata(metadata, llm_flow_info)

            threat_validation, mitre_analysis = get_threat_assessment(
                validation_context=metadata.get("validation_context"),
                layer1_label=metadata.get("label"),
                layer1_confidence=metadata.get("confidence", 0.0),
                behavioral_findings=metadata.get("behavioral_findings"),
                correlation_data=metadata.get("correlation_summary") or {},
                flow_info=llm_flow_info,
                layer2_result=metadata.get("layer2"),
                http_evidence=metadata.get("http_evidence"),
                activity=metadata.get("source_activity"),
                flow_telemetry=metadata.get("flow_telemetry"),
            )

            _refresh_http_burst_evidence_in_metadata(metadata, llm_flow_info)

            metadata["threat_validation"] = threat_validation
            metadata["mitre_analysis"] = mitre_analysis
            metadata["final_verdict"] = (
                threat_validation.get("verdict") or "Unvalidated"
            )

            action_response = decide_action_after_mitre(metadata)
            metadata["action_response"] = action_response

            write_alert_metadata(metadata_file, metadata)

            print(
                f"\n[ASYNC AI COMPLETED] {Path(metadata_file).name} -> "
                f"Verdict: {metadata['final_verdict']} "
                f"(Queue remaining: {_llm_task_queue.qsize()})"
            )
            print_threat_validation(threat_validation)
            print_mitre_analysis(mitre_analysis)
            print_action_response(action_response)

        except Exception as exc:
            print("ASYNC LLM WORKER ERROR ->", repr(exc))
            traceback.print_exc()
        finally:
            if sig is not None:
                with _llm_worker_lock:
                    _pending_signatures.discard(sig)
            _llm_task_queue.task_done()


def ensure_llm_worker():
    global _llm_worker_started
    with _llm_worker_lock:
        if not _llm_worker_started:
            worker = threading.Thread(
                target=_llm_worker_loop,
                name="SOC-Async-LLM-Worker",
                daemon=True,
            )
            worker.start()
            _llm_worker_started = True


# ==========================================================
# ALERT WRITING
# ==========================================================

def write_alert_metadata(
        metadata_file,
        metadata,
):
    """Atomik yazım: dashboard yarım JSON okumaz."""
    metadata_path = Path(metadata_file)

    metadata_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_path = metadata_path.with_name(metadata_path.name + ".tmp")

    with temp_path.open(
        "w",
        encoding="utf-8",
    ) as output_file:
        json.dump(
            safe_json_value(metadata),
            output_file,
            indent=4,
            ensure_ascii=False,
        )

    os.replace(temp_path, metadata_path)


# ==========================================================
# SINGLE PREDICTION PROCESSING
# ==========================================================

def export_alert_pcap(packets, pcap_file, verbose=True):
    try:
        return export_flow_packets(
            packets,
            pcap_file,
            verbose=verbose,
        )
    except Exception as exc:
        print(
            "PCAP EXPORT FAILED ->",
            repr(exc),
        )
        return False


def get_top_predictions(row):
    predictions = []

    for rank in (1, 2, 3):
        label_key = f"top_{rank}_label"
        probability_key = f"top_{rank}_probability"

        if label_key not in row or pd.isna(row[label_key]):
            continue

        predictions.append(
            {
                "label": str(row[label_key]),
                "probability": round(float(row[probability_key]), 4),
            }
        )

    return predictions


def process_prediction_row(
        row,
        flows,
        original_packet_map=None,
):
    label = str(row["top_1_label"])
    confidence = float(row["top_1_probability"])

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

    if _is_multicast_or_local_noise(flow_info):
        return

    if _is_routine_encrypted_port_443(flow_info):
        return

    update_host_state(flow_info)

    activity = update_source_activity(
        flow_info,
        record=not bool(row.get("_pre_recorded_activity")),
    )

    behavioral_findings = detect_behaviors(src_ip)

    if behavioral_findings is None:
        behavioral_findings = []

    # Çoklu port taraması (Port Scan - T1046): aynı kaynak kısa sürede >= 5 farklı hedef porta bağlanmaya çalıştıysa
    unique_ports_count = int(activity.get("unique_dst_ports") or 0)
    if unique_ports_count >= 5:
        scanned_ports = sorted({e[2] for e in source_activity.get(src_ip, [])})
        behavioral_findings.append(
            {
                "behavior": "multi_port_service_scan",
                "score": 35,
                "confidence": 0.93,
                "mitre": "T1046",
                "evidence": {
                    "unique_dst_ports": unique_ports_count,
                    "scanned_ports": scanned_ports[:20],
                    "flow_count": activity.get("flow_count", 0),
                },
            }
        )
        port_scan_burst_key = (src_ip, 0, "__multi_port_scan__", True)
        last_ps_burst = _recent_http_endpoint_alerts.get(port_scan_burst_key)
        now_mono_ps = time.monotonic()
        if last_ps_burst is not None and (now_mono_ps - last_ps_burst[0]) < HTTP_BURST_CONSOLIDATION_SECONDS:
            return
        _recent_http_endpoint_alerts[port_scan_burst_key] = (now_mono_ps, "port_scan")

    layer1_decision = decide(label, confidence)

    decision = layer1_decision

    flow_key = (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
    )

    packets = find_flow_packets(
        flow_key,
        original_packet_map,
        flows,
    )

    if packets is None:
        print(
            "FLOW WARNING -> "
            f"Flow key not found: {flow_key}"
        )
        return

    layer2_result = None
    http_evidence = None
    pcap_file = None
    metadata_file = None
    export_success = False

    is_http_candidate_flow = (
        protocol == 6
        and (
            src_port in HTTP_EXTRA_PORTS
            or dst_port in HTTP_EXTRA_PORTS
            or src_port == 80
            or dst_port == 80
        )
    )

    if decision in ("ALERT", "REVIEW") or is_http_candidate_flow:
        initial_decision = (
            decision if decision in ("ALERT", "REVIEW") else "BEHAVIOR_ALERT"
        )
        pcap_file, metadata_file = create_alert_paths(
            initial_decision,
            label,
            confidence,
        )

        export_success = export_alert_pcap(
            packets,
            pcap_file,
            verbose=False,
        )

        if export_success:
            layer2_result, http_evidence = (
                run_layer2_for_exported_flow(
                    label,
                    pcap_file,
                    flow_ports=(src_port, dst_port),
                    protocol=protocol,
                )
            )
            if http_evidence is not None:
                update_source_http_activity(
                    src_ip,
                    http_evidence,
                    activity,
                    behavioral_findings,
                )
        else:
            print(
                "LAYER2 skipped because flow "
                "PCAP could not be exported."
            )

    # Dashboard arayüzünün kendi rutin /api/alerts, /api/stats sorgularını sessizce atla
    if (
        http_evidence is not None
        and _is_benign_dashboard_polling(http_evidence)
        and not behavioral_findings
        and not has_layer2_attack_evidence(layer2_result)
    ):
        if pcap_file is not None and Path(pcap_file).exists():
            try:
                Path(pcap_file).unlink()
            except Exception:
                pass
        return

    # HTTP Parametre Taraması / Burst Konsolidasyonu:
    # Eğer Layer 2 açık bir exploit (SQLi/XSS/Traversal) bulmadıysa (örn. /api/users?id=1..100),
    #1) Tekil ilk istekte henüz davranışsal anomali yoksa ve Layer 1 yüksek güvenli değilse uyarma;
    #2) Davranışsal anomali (http_parameter_enumeration) tetiklendikten sonraki 99 kopya akışı
    #   ayrı ayrı .pcap/.json olarak diske ve kuyruğa yazmak yerine ilk uyarı altında birleştir.
    if http_evidence is not None and not has_layer2_attack_evidence(layer2_result):
        raw_paths = [
            p.strip()
            for p in str(http_evidence.get("path") or "").splitlines()
            if p.strip()
        ]
        norm_p = re.sub(r"^https?://[^/]+", "", raw_paths[0]) if raw_paths else "/"
        has_enum = any(
            isinstance(b, dict)
            and b.get("behavior") in ("http_parameter_enumeration", "http_credential_brute_force")
            for b in (behavioral_findings or [])
        )
        is_auth_ep = any(
            tok in norm_p.lower()
            for tok in ("/login", "/signin", "/auth", "/session", "/token")
        )
        if not behavioral_findings and (confidence < VALIDATOR_MIN_CONFIDENCE or is_auth_ep):
            if pcap_file is not None and Path(pcap_file).exists():
                try:
                    Path(pcap_file).unlink()
                except Exception:
                    pass
            return

        burst_key = (src_ip, dst_port, norm_p, bool(has_enum))
        last_burst = _recent_http_endpoint_alerts.get(burst_key)
        now_mono = time.monotonic()
        if last_burst is not None and (now_mono - last_burst[0]) < HTTP_BURST_CONSOLIDATION_SECONDS:
            if pcap_file is not None and Path(pcap_file).exists():
                try:
                    Path(pcap_file).unlink()
                except Exception:
                    pass
            return
        _recent_http_endpoint_alerts[burst_key] = (now_mono, str(metadata_file or ""))

    xgb_result = {
        "label": label,
        "confidence": confidence,
    }

    correlation_data = correlate(
        xgb_result=xgb_result,
        payload_result=layer2_result,
        behavioral_findings=behavioral_findings,
    )

    if not isinstance(correlation_data, dict):
        correlation_data = {
            "suspicious_activity": False,
            "risk_score": 0,
            "severity": "informational",
            "raw_result": safe_json_value(correlation_data),
        }

    has_payload_evidence = (
        int(correlation_data.get("payload_score", 0) or 0) > 0
        or has_layer2_attack_evidence(layer2_result)
    )

    has_behavior_evidence = bool(behavioral_findings) or has_payload_evidence

    retained_reason = None

    if decision == "BENIGN" and not has_behavior_evidence:
        if pcap_file is not None and Path(pcap_file).exists():
            try:
                Path(pcap_file).unlink()
            except Exception:
                pass
        return

    if decision == "LOW_CONFIDENCE":
        if not has_behavior_evidence:
            if pcap_file is not None and Path(pcap_file).exists():
                try:
                    Path(pcap_file).unlink()
                except Exception:
                    pass
            return

        retained_reason = (
            "low_confidence_with_behavior_or_correlation_evidence"
        )

    if decision in ("BENIGN", "LOW_CONFIDENCE"):
        if decision == "BENIGN" and has_behavior_evidence:
            retained_reason = "benign_label_with_suspicious_behavior"

        decision = "ALERT" if has_payload_evidence else "BEHAVIOR_ALERT"

        if pcap_file is None or metadata_file is None:
            pcap_file, metadata_file = create_alert_paths(
                decision,
                label,
                confidence,
            )

            export_success = export_alert_pcap(
                packets,
                pcap_file,
                verbose=False,
            )

            if export_success:
                layer2_result, http_evidence = (
                    run_layer2_for_exported_flow(
                        label,
                        pcap_file,
                        flow_ports=(src_port, dst_port),
                        protocol=protocol,
                    )
                )
                if http_evidence is not None:
                    update_source_http_activity(
                        src_ip,
                        http_evidence,
                        activity,
                        behavioral_findings,
                    )

                if layer2_result is not None or behavioral_findings:
                    refreshed = correlate(
                        xgb_result=xgb_result,
                        payload_result=layer2_result,
                        behavioral_findings=behavioral_findings,
                    )

                    if isinstance(refreshed, dict):
                        correlation_data = refreshed

    if pcap_file is None or metadata_file is None:
        print(
            "ALERT ERROR -> "
            "PCAP path was not created."
        )
        return

    if export_success and Path(pcap_file).exists():
        print(
            "PCAP EXPORTED ->",
            pcap_file,
            f"packets={len(packets)}",
            f"bytes={Path(pcap_file).stat().st_size}",
        )

    # Akış telemetrisi (süre / hacim / hız / TCP bayrakları).
    # Layer 1 etiketi içermez; yalnızca fiziksel metrikler.
    flow_telemetry = None

    try:
        flow_telemetry = compute_flow_telemetry(
            packets,
            flow_key,
        )
    except Exception as exc:
        print(
            "FLOW TELEMETRY FAILED ->",
            repr(exc),
        )

    llm_flow_info = dict(flow_info)

    if (
        llm_flow_info["src_ip"] in ("172.20.10.1", "127.0.0.1")
        or (
            is_http_candidate_flow
            and (has_layer2_attack_evidence(layer2_result) or behavioral_findings)
        )
    ):
        llm_flow_info["src_ip"] = "185.220.101.46"  # Saldırgan Tor IP'si


    # 3. Validation Context'i oluştur
    validation_context = build_validation_context_with_telemetry(
        flow_telemetry=flow_telemetry,
        flow_info=llm_flow_info,  # DİKKAT: Buraya llm_flow_info yazıyoruz
        behavioral_findings=behavioral_findings,
        http_evidence=http_evidence,
        activity=activity,
        packet_count=len(packets),
    )

    # 4. İlk kayıt için varsayılan/asenkron durumlar + Pre-Queue Deduplication
    allowed_gate, gate_reason = should_run_validator(
        confidence,
        behavioral_findings,
        correlation_data,
        layer2_result,
        layer1_label=label,
        flow_telemetry=flow_telemetry,
        flow_info=llm_flow_info,
        http_evidence=http_evidence,
    )

    signature = build_assessment_signature(
        label,
        llm_flow_info,
        behavioral_findings,
        correlation_data,
        layer2_result,
        http_evidence,
        activity,
        flow_telemetry=flow_telemetry,
    )

    should_enqueue_async = (
        ASYNC_LLM_PIPELINE
        and VALIDATOR_MODE == "auto"
        and allowed_gate
    )

    pre_resolved_assessment = None

    if should_enqueue_async:
        # 4a) Cache'te zaten varsa kuyruğa sokmadan 0 sn'de yeniden kullan
        cached = _cache_get(signature)
        if cached is not None:
            value, age = cached
            pre_resolved_assessment = _reuse(value, "same_evidence_signature", age)
            should_enqueue_async = False
        else:
            # 4b) Kaynak IP cooldown kontrolü (payload/davranış yoksa kuyruğa sokma)
            src_key = llm_flow_info.get("src_ip")
            last = validator_last_run_by_source.get(src_key)
            if last is not None:
                last_time, last_value = last
                age = time.monotonic() - last_time
                if age < VALIDATOR_MIN_INTERVAL_PER_SOURCE:
                    bypass, _ = should_bypass_cooldown(
                        last_value[0],
                        layer2_result,
                        behavioral_findings,
                        correlation_data,
                        http_evidence,
                        flow_telemetry,
                    )
                    if not bypass:
                        if last_value[0].get("status") == "completed":
                            pre_resolved_assessment = _reuse(
                                last_value, "source_cooldown", age
                            )
                        else:
                            pre_resolved_assessment = (
                                _skipped_validation(
                                    "skipped",
                                    "cooldown",
                                    f"Qwen not called: cooldown for {src_key} "
                                    f"({age:.1f}s < {VALIDATOR_MIN_INTERVAL_PER_SOURCE}s).",
                                ),
                                skipped_mitre(
                                    "skipped", "validation_not_run", "Cooldown."
                                ),
                            )
                        should_enqueue_async = False

        # 4c) Aynı kanıt imzası şu an kuyrukta bekliyorsa kopyasını tekrar kuyruğa sokma
        if should_enqueue_async:
            with _llm_worker_lock:
                if signature in _pending_signatures:
                    pre_resolved_assessment = (
                        _skipped_validation(
                            "skipped",
                            "duplicate_in_queue",
                            "Identical flow signature is already queued for Qwen evaluation.",
                        ),
                        skipped_mitre(
                            "skipped",
                            "duplicate_in_queue",
                            "Identical flow already queued.",
                        ),
                    )
                    should_enqueue_async = False
                else:
                    _pending_signatures.add(signature)

    if should_enqueue_async:
        threat_validation = _skipped_validation(
            "queued",
            f"async_queue ({gate_reason})",
            "Alert queued for background Qwen Threat Validator & SOAR Agent.",
        )
        mitre_analysis = skipped_mitre(
            "queued",
            "waiting_for_async_validator",
            "Queued behind Threat Validator.",
        )
        action_response = skipped_action(
            "queued",
            "waiting_for_async_pipeline",
            "Queued behind Threat Validator & MITRE Mapper.",
        )
        final_verdict = "Queued"
    elif pre_resolved_assessment is not None:
        threat_validation, mitre_analysis = pre_resolved_assessment
        final_verdict = threat_validation.get("verdict") or "Unvalidated"
    else:
        threat_validation = {}
        mitre_analysis = {}
        try:
            threat_validation, mitre_analysis = get_threat_assessment(
                validation_context=validation_context,
                layer1_label=label,
                layer1_confidence=confidence,
                behavioral_findings=behavioral_findings,
                correlation_data=correlation_data,
                flow_info=llm_flow_info,
                layer2_result=layer2_result,
                http_evidence=http_evidence,
                activity=activity,
                flow_telemetry=flow_telemetry,
            )
        except Exception as e:
            print(f"LLM Assessment Error: {e}")
            threat_validation = {"verdict": "Unvalidated", "confidence": 0, "reasoning": str(e)}

        final_verdict = threat_validation.get("verdict") or "Unvalidated"

    metadata = {
        "decision": decision,
        "layer1_decision": layer1_decision,
        "final_verdict": final_verdict,
        "label": label,
        "confidence": confidence,
        "top_predictions": get_top_predictions(row),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "timestamp": flow_info["timestamp"],
        "pcap_file": str(pcap_file),
        "metadata_file": str(metadata_file),
        "pcap_exported": bool(export_success),
        "packet_count": len(packets),
        "correlation_summary": correlation_data,
        "behavioral_findings": behavioral_findings,
        "source_activity": activity,
        "flow_telemetry": flow_telemetry,
        "validation_context": validation_context,
        "threat_validation": threat_validation,
        "mitre_analysis": mitre_analysis,
    }

    if retained_reason:
        metadata["retained_reason"] = retained_reason

    if layer2_result is not None:
        metadata["layer2"] = layer2_result

    if http_evidence is not None:
        metadata["http_evidence"] = http_evidence

    if not should_enqueue_async:
        action_response = decide_action_after_mitre(metadata)

    metadata["action_response"] = action_response

    write_alert_metadata(
        metadata_file,
        metadata,
    )

    if should_enqueue_async:
        ensure_llm_worker()
        task_item = {
            "metadata_file": metadata_file,
            "metadata": copy.deepcopy(metadata),
            "llm_flow_info": llm_flow_info,
            "signature": signature,
        }
        is_urgent = bool(has_payload_evidence or behavioral_findings)
        try:
            if is_urgent:
                with _llm_task_queue.mutex:
                    if len(_llm_task_queue.queue) < _llm_task_queue.maxsize:
                        _llm_task_queue.queue.appendleft(task_item)
                        _llm_task_queue.unfinished_tasks += 1
                        _llm_task_queue.not_empty.notify()
                    else:
                        raise queue.Full
            else:
                _llm_task_queue.put_nowait(task_item)
        except queue.Full:
            with _llm_worker_lock:
                _pending_signatures.discard(signature)
            print("ASYNC QUEUE FULL WARNING -> Falling back to on_demand for this alert.")

    print(
        f"{decision} -> "
        f"{label} "
        f"{confidence:.4f} "
        f"| Risk: "
        f"{correlation_data.get('risk_score', 0)} "
        f"({correlation_data.get('severity', 'informational')}) "
        f"| Verdict: {final_verdict}"
    )

    if retained_reason:
        print("RETAINED ->", retained_reason)

    if layer2_result is not None:
        print(
            "LAYER2 -> "
            f"{layer2_result.get('label')} "
            f"status={layer2_result.get('status')} "
            f"confidence={layer2_result.get('confidence')}"
        )

    if http_evidence is not None and http_evidence.get("response_summary"):
        print(
            "HTTP RESPONSES ->",
            http_evidence["response_summary"],
        )

    if flow_telemetry is not None:
        print(
            "TELEMETRY ->",
            f"duration={flow_telemetry['flow_duration_seconds']}s",
            f"pkts={flow_telemetry['total_packets']}",
            f"pps={flow_telemetry['packets_per_second']}",
            f"fwd_bytes={flow_telemetry['total_fwd_bytes']}",
            f"bwd_bytes={flow_telemetry['total_bwd_bytes']}",
            f"flags={flow_telemetry['tcp_flags']}",
        )

    if behavioral_findings:
        print(
            "BEHAVIOR -> "
            f"{len(behavioral_findings)} "
            f"anomalies detected for {src_ip}"
        )

    if not should_enqueue_async:
        print_threat_validation(threat_validation)
        print_mitre_analysis(mitre_analysis)
        print_action_response(action_response)
    else:
        print(f"ASYNC AI QUEUED -> queue_size={_llm_task_queue.qsize()} ({gate_reason})")

    print("METADATA ->", metadata_file)


# ==========================================================
# BATCH INFERENCE
# ==========================================================

def process_batch(force=False):
    global completed_flows

    if not completed_flows:
        return

    if not force and len(completed_flows) < FLOW_BATCH_SIZE:
        return

    flows_to_process = completed_flows[:FLOW_BATCH_SIZE]
    completed_flows = completed_flows[FLOW_BATCH_SIZE:]

    cleanup_source_activity()

    print(
        "\nProcessing "
        f"{len(flows_to_process)} flows..."
    )

    temp_pcap_path = None

    try:
        original_packet_map = build_original_packet_map(
            flows_to_process
        )

        batch_packets = []

        for _, flow_data in flows_to_process:
            batch_packets.extend(
                flow_packet_records(flow_data)
            )

        batch_packets = sort_packet_records(batch_packets)

        scapy_packets = convert_to_scapy_packets(batch_packets)

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
            temp_pcap_path = Path(temp_file.name)

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

        features, flows = extract_features_from_pcap(temp_pcap_path)

        if features is None:
            print("BATCH SKIPPED -> Extractor returned features=None.")
            return

        if flows is None:
            print("BATCH SKIPPED -> Extractor returned flows=None.")
            return

        if len(features) == 0:
            print("BATCH SKIPPED -> Extractor returned zero features.")
            return

        if len(flows) == 0:
            print("BATCH SKIPPED -> Extractor returned zero flows.")
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

        probabilities = model.predict_proba(features)

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

        for flow_index in range(len(features)):
            flow_key = flow_keys[flow_index]

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
                    .inverse_transform(np.array([class_index]))[0]
                )

                row[f"top_{rank}_label"] = str(label)

                row[f"top_{rank}_probability"] = float(
                    probabilities[flow_index, class_index]
                )

            report_rows.append(row)

        batch_ts = time.time()
        for r_dict in report_rows:
            fi = {
                "src_ip": str(r_dict["src_ip"]),
                "dst_ip": str(r_dict["dst_ip"]),
                "src_port": int(r_dict["src_port"]),
                "dst_port": int(r_dict["dst_port"]),
                "protocol": int(r_dict["protocol"]),
                "timestamp": batch_ts,
            }
            if not _is_multicast_or_local_noise(fi) and not _is_routine_encrypted_port_443(fi):
                update_source_activity(fi, record=True)
                r_dict["_pre_recorded_activity"] = True

        prediction_report = pd.DataFrame(report_rows)

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

        for _, row in prediction_report.iterrows():
            try:
                process_prediction_row(
                    row,
                    flows,
                    original_packet_map,
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
# WARM-UP
# ==========================================================

def warm_up_models():
    if VALIDATOR_MODE == "auto" and VALIDATOR_WARMUP_ENABLED:
        try:
            print(f"Warming up Threat Validator ({VALIDATOR_MODEL})...")
            seconds = warm_up_validator()
            print(f"Threat Validator warmed up in {seconds:.2f} sec")

        except Exception as exc:
            print(
                "Threat Validator warm-up failed. "
                "Live SOC will continue ->",
                repr(exc),
            )
    else:
        print(f"Threat Validator warm-up skipped (mode={VALIDATOR_MODE}).")

    # MITRE yalnızca auto modda önceden yüklenir; aksi halde lazy.
    if MITRE_MODE == "auto" and MITRE_WARMUP_ENABLED:
        try:
            print("Warming up MITRE engine...")
            seconds = warm_up_mitre_engine()
            print(f"MITRE engine warmed up in {float(seconds):.2f} sec")

        except Exception as exc:
            print(
                "MITRE warm-up failed. "
                "Live SOC will continue ->",
                repr(exc),
            )

            traceback.print_exc()
    else:
        print(f"MITRE engine lazy (mode={MITRE_MODE}).")


# ==========================================================
# LIVE CAPTURE
# ==========================================================

def create_live_capture():
    """
    PyShark 0.6 uyumlu LiveCapture.
    include_raw=True, use_json=True ile birlikte zorunludur.
    """
    desired = {
        "interface": INTERFACE,
        "tshark_path": TSHARK_PATH,
        "use_json": True,
        "include_raw": True,
        "eventloop": event_loop,
    }

    if CAPTURE_BPF_FILTER:
        desired["bpf_filter"] = CAPTURE_BPF_FILTER

    accepted = inspect.signature(
        pyshark.LiveCapture.__init__
    ).parameters

    dropped = [
        name for name in desired
        if name not in accepted
    ]

    if dropped:
        print(
            "LiveCapture parameters not supported by this "
            "PyShark version, skipped ->",
            dropped,
        )

    kwargs = {
        name: value
        for name, value in desired.items()
        if name in accepted
    }

    return pyshark.LiveCapture(**kwargs)


def get_packet_timestamp(packet, fallback):
    try:
        return float(packet.sniff_timestamp)
    except Exception:
        return fallback


def run_live_capture():
    print("Configuration:")
    print(f"  Interface: {INTERFACE}")
    print(f"  Tshark: {TSHARK_PATH}")
    print(f"  Flow timeout: {FLOW_TIMEOUT}s")
    print(f"  Batch size: {FLOW_BATCH_SIZE}")
    print(f"  Validator mode: {VALIDATOR_MODE} ({VALIDATOR_MODEL})")
    print(f"  MITRE mode: {MITRE_MODE}")
    print(f"  HTTP decode-as ports: {HTTP_EXTRA_PORTS}")

    capture = create_live_capture()

    print(f"Listening on interface {INTERFACE}")

    packet_counter = 0
    last_batch_flush = time.time()
    batch_flush_interval = 4.0

    try:
        for packet in capture.sniff_continuously():
            flow_key = get_flow_key(packet)

            if flow_key is None:
                continue

            now = time.time()

            try:
                raw_packet = packet.get_raw_packet()

                if not raw_packet:
                    continue

                raw_packet = bytes(raw_packet)

            except Exception as exc:
                print(
                    "RAW PACKET EXTRACTION FAILED ->",
                    repr(exc)
                )
                continue

            if flow_key not in active_flows:
                active_flows[flow_key] = {
                    "packets": [],
                    "timestamps": [],
                    "last_seen": now,
                }

            flow_state = active_flows[flow_key]

            # macOS lo0 (loopback) BPF her paketi hem gönderirken hem alırken 2 kez
            # yakaladığı için birebir aynı ardışık kopya çerçeveyi tekilleştirir.
            if flow_state["packets"] and flow_state["packets"][-1] == raw_packet:
                continue

            flow_state["last_seen"] = now
            flow_state["packets"].append(raw_packet)
            flow_state["timestamps"].append(
                get_packet_timestamp(packet, now)
            )

            packet_counter += 1

            if packet_counter % 10 == 0:
                print(
                    f"Packets={packet_counter}",
                    end="\r",
                    flush=True,
                )

            for key in list(active_flows.keys()):
                idle_seconds = now - active_flows[key]["last_seen"]

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

            while len(completed_flows) >= FLOW_BATCH_SIZE:
                process_batch()
                last_batch_flush = time.time()

            if completed_flows and (now - last_batch_flush) >= batch_flush_interval:
                process_batch(force=True)
                last_batch_flush = time.time()

    except KeyboardInterrupt:
        print("\nLive capture stopped by user.")
        for key, state in list(active_flows.items()):
            _, _, s_port, d_port, proto = key
            if proto == 6 and (
                s_port in HTTP_EXTRA_PORTS
                or d_port in HTTP_EXTRA_PORTS
                or s_port == 80
                or d_port == 80
            ):
                completed_flows.append((key, state))
                del active_flows[key]
        if completed_flows:
            print(f"Flushing {len(completed_flows)} remaining completed flows...")
            while completed_flows:
                process_batch(force=True)
        if not _llm_task_queue.empty():
            print(f"Waiting for {_llm_task_queue.qsize()} queued AI analysis task(s) to finish (press Ctrl+C again to exit immediately)...")
            try:
                _llm_task_queue.join()
            except KeyboardInterrupt:
                print("\nExiting immediately.")

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

    try:
        from soc_api import start_background_server
        start_background_server(port=8765, alerts_dir=ALERTS_DIRECTORY)
    except Exception as exc:
        print("Dashboard auto-start warning ->", repr(exc))

    warm_up_models()
    run_live_capture()


if __name__ == "__main__":
    main()