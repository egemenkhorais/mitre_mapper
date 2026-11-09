# threat_validator.py
"""
Qwen Threat Validator.

Soru artık "bu hangi MITRE tekniği?" değil:
    "Bu trafik GERÇEKTEN saldırı mı, yoksa normal enterprise davranışı mı?"

- Ollama HTTP API'sine doğrudan konuşur (ek bağımlılık yok, urllib).
- Ağ gerçekleri (multicast, private, link-local, servis adı...) KOD ile
  hesaplanır ama KARAR verilmez; yorum Qwen'e bırakılır (hardcode yok).
- live_soc.py (otomatik) ve soc_api.py (dashboard butonu) aynı modülü kullanır.
"""

import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.request

# ==========================================================
# CONFIG
# ==========================================================

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
VALIDATOR_MODEL = "qwen3:8b"
VALIDATOR_TIMEOUT = 120
VALIDATOR_KEEP_ALIVE = "30m"
VALIDATOR_NUM_PREDICT = 280
VALIDATOR_NUM_CTX = 3072

# Qwen3 düşünme modunu kapatır (ollama run --think=false eşdeğeri).
VALIDATOR_DISABLE_THINKING = True

# Prompt'a giren ham HTTP isteği için karakter sınırı.
HTTP_PROMPT_MAX_CHARS = 3500

VERDICTS = (
    "Benign",
    "Likely Benign",
    "Suspicious",
    "Malicious",
)

_VERDICT_LOOKUP = {
    verdict.lower().replace(" ", "_"): verdict
    for verdict in VERDICTS
}

# Skeptical prompt may produce this wording; it is a Benign outcome.
_VERDICT_LOOKUP["false_positive"] = "Benign"

SYSTEM_PROMPT = """You are a senior SOC analyst evaluating raw network traffic and HTTP payloads.
Your goal is to accurately distinguish between normal enterprise/local network noise (such as mDNS, SSDP, OSPF, normal web browsing) and real cyber attacks.

You are given raw network evidence: addresses, ports, protocol, address properties, source activity, behavioral findings, flow telemetry, and (when visible) the observed HTTP request/response.

Rules:
1. CRITICAL: Inspect `http_evidence` (including URL-encoded characters like %27 for ', %22 for ", %3C for <, --, /*, UNION, SELECT, OR 1=1, ../, etc.) very carefully BEFORE assuming traffic is benign.
2. Answer "Malicious" IMMEDIATELY when `http_evidence` contains SQL injection (e.g., admin'--, admin%27--, OR 1=1, UNION SELECT), XSS, path traversal, command injection, or authentication bypass attempts — EVEN IF the server responded with 404 Not Found, 401, or 500, and EVEN IF packet count is low! A failed exploit attempt is STILL a "Malicious" attack.
3. Also answer "Malicious" or "Suspicious" when `source_activity` or `flow_telemetry` shows rapid sequential requests to endpoints (e.g., ID enumeration /api/users?id=1,2,3..., port scanning, or SYN/packet floods).
4. Answer "Benign" or "Likely Benign" ONLY when the traffic is genuinely harmless (e.g., standard multicast/broadcast discovery like SSDP/mDNS, normal static page loads without exploit strings, or routine encrypted traffic with normal telemetry).
5. Put the exact indicator from the evidence (e.g. "GET /login?user=admin%27--" or "15 flows in 60s to port 8765") in `malicious_indicators`.
6. Never claim an indicator that is not literally present in the input.

Verdicts:
- Benign: clearly legitimate traffic (a false alarm).
- Likely Benign: probably legitimate, weak or no malicious signal.
- Suspicious: some evidence contradicts normal behavior, needs analyst review.
- Malicious: the evidence consistently supports an attack or contains an exploit payload.

Return ONLY a JSON object with exactly these keys:
{
  "verdict": "Benign" | "Likely Benign" | "Suspicious" | "Malicious",
  "confidence": integer 0-100 (your confidence in the verdict),
  "benign_explanation": "most plausible legitimate explanation, or empty string",
  "malicious_indicators": ["short evidence-based indicators, empty list if none"],
  "reasoning": "at most 3 sentences",
  "recommended_next_step": "one short sentence"
}"""


# ==========================================================
# NETWORK FACTS (karar değil, gerçek)
# ==========================================================

PROTOCOL_NAMES = {
    6: "TCP",
    17: "UDP",
}


def describe_ip(ip):
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return {"valid": False}

    return {
        "valid": True,
        "version": address.version,
        "private": address.is_private,
        "global": address.is_global,
        "multicast": address.is_multicast,
        "link_local": address.is_link_local,
        "loopback": address.is_loopback,
        "reserved": address.is_reserved,
        "limited_broadcast": str(address) == "255.255.255.255",
    }


def service_name(port, protocol):
    proto = {6: "tcp", 17: "udp"}.get(_to_int(protocol))

    if proto is None:
        return None

    try:
        return socket.getservbyport(int(port), proto)
    except (OSError, OverflowError, ValueError, TypeError):
        return None


def _to_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _scope(properties):
    if not properties.get("valid"):
        return "unknown"

    if properties.get("multicast") or properties.get("limited_broadcast"):
        return "multicast_or_broadcast"

    if properties.get("loopback"):
        return "loopback"

    if properties.get("link_local"):
        return "link_local"

    if properties.get("private"):
        return "internal"

    return "external"


def build_network_facts(flow_info):
    flow_info = flow_info or {}

    protocol = _to_int(flow_info.get("protocol"))
    src_props = describe_ip(flow_info.get("src_ip"))
    dst_props = describe_ip(flow_info.get("dst_ip"))

    return {
        "protocol": PROTOCOL_NAMES.get(protocol, str(protocol)),
        "src_ip": flow_info.get("src_ip"),
        "src_port": flow_info.get("src_port"),
        "dst_ip": flow_info.get("dst_ip"),
        "dst_port": flow_info.get("dst_port"),
        "src_scope": _scope(src_props),
        "dst_scope": _scope(dst_props),
        "direction": f"{_scope(src_props)}_to_{_scope(dst_props)}",
        "src_ip_properties": src_props,
        "dst_ip_properties": dst_props,
        "src_port_service": service_name(flow_info.get("src_port"), protocol),
        "dst_port_service": service_name(flow_info.get("dst_port"), protocol),
    }


# ==========================================================
# CONTEXT
# ==========================================================

def _compact(value, max_len=600):
    """Prompt'u kısa tutmak için uzun alanları kırpar."""
    try:
        text = json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        text = str(value)

    if len(text) <= max_len:
        return value

    return text[:max_len] + "...(truncated)"


def _compact_http(http_evidence):
    """HTTP kanıtını LLM için derler: ham istek + çözümlenmiş (URL-decoded) query/path öncelikli."""
    if not isinstance(http_evidence, dict) or not http_evidence:
        return None

    from urllib.parse import unquote_plus

    raw_request = http_evidence.get("raw_request")
    query = http_evidence.get("query")
    decoded_query = unquote_plus(str(query)) if query else None
    path = http_evidence.get("path")
    decoded_path = unquote_plus(str(path)) if path else None

    if raw_request:
        raw_str = str(raw_request)[:HTTP_PROMPT_MAX_CHARS]
        result = {
            "method": http_evidence.get("method"),
            "path": path,
            "query": query,
            "decoded_query": decoded_query,
            "response_summary": http_evidence.get("response_summary"),
            "request_count": http_evidence.get("request_count"),
            "raw_request": raw_str,
        }
        if decoded_path and decoded_path != path:
            result["decoded_path"] = decoded_path
        decoded_raw = unquote_plus(raw_str)
        if decoded_raw != raw_str:
            result["decoded_raw_request"] = decoded_raw[:HTTP_PROMPT_MAX_CHARS]
        return result

    # Eski alert kayıtları: ham istek yok, eldeki alanları ver.
    return _compact(http_evidence, HTTP_PROMPT_MAX_CHARS)


def build_validation_context(
        flow_info,
        behavioral_findings=None,
        http_evidence=None,
        activity=None,
        packet_count=None,
        **_ignored,
):
    """
    BLIND context: yalnızca ağ kanıtı. Layer 1 etiketi, güveni, kararı,
    top tahminleri, korelasyon skoru ve Layer 2 sonucu bilerek YOKTUR.
    Eski çağrılar bunları keyword olarak verirse sessizce yok sayılır.
    """
    behaviors = []

    for item in behavioral_findings or []:
        if not isinstance(item, dict):
            continue

        behaviors.append(
            {
                "behavior": item.get("behavior"),
                "score": item.get("score"),
                "confidence": item.get("confidence"),
                "evidence": _compact(item.get("evidence"), 300),
            }
        )

    return {
        "blind": True,
        "flow": {
            "src_ip": flow_info.get("src_ip"),
            "dst_ip": flow_info.get("dst_ip"),
            "src_port": flow_info.get("src_port"),
            "dst_port": flow_info.get("dst_port"),
            "protocol": flow_info.get("protocol"),
            "timestamp": flow_info.get("timestamp"),
            "packet_count": packet_count,
        },
        "network_facts": build_network_facts(flow_info),
        "source_activity": activity or {},
        "behavioral_findings": behaviors,
        "http_evidence": _compact_http(http_evidence),
    }


def context_from_alert(metadata):
    """
    Dashboard butonu için bağlamı kurar. Kaydedilmiş bağlam yalnızca kör
    (blind) ise kullanılır; eski kayıtlardaki etiketli bağlam (classifier /
    correlation / layer2_payload) atılır ve metadata'dan kör olarak yeniden
    kurulur. Layer 1 alanları metadata'da durur ama LLM'e GİTMEZ.
    """
    saved = metadata.get("validation_context")

    if (
        isinstance(saved, dict)
        and saved.get("blind")
        and saved.get("flow")
    ):
        return saved

    flow_info = {
        "src_ip": metadata.get("src_ip"),
        "dst_ip": metadata.get("dst_ip"),
        "src_port": metadata.get("src_port"),
        "dst_port": metadata.get("dst_port"),
        "protocol": metadata.get("protocol"),
        "timestamp": metadata.get("timestamp"),
    }

    return build_validation_context(
        flow_info=flow_info,
        behavioral_findings=metadata.get("behavioral_findings"),
        http_evidence=metadata.get("http_evidence"),
        activity=metadata.get("source_activity"),
        packet_count=metadata.get("packet_count"),
    )


# ==========================================================
# OLLAMA
# ==========================================================

def _post_chat(payload):
    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=VALIDATOR_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def _chat(messages, num_predict=VALIDATOR_NUM_PREDICT, json_format=True):
    payload = {
        "model": VALIDATOR_MODEL,
        "messages": messages,
        "stream": False,
        "keep_alive": VALIDATOR_KEEP_ALIVE,
        "options": {
            "temperature": 0,
            "num_predict": num_predict,
            "num_ctx": VALIDATOR_NUM_CTX,
        },
    }

    if json_format:
        payload["format"] = "json"

    if VALIDATOR_DISABLE_THINKING:
        payload["think"] = False

    try:
        return _post_chat(payload)

    except urllib.error.HTTPError as exc:
        # Eski Ollama sürümleri "think" alanını tanımayabilir.
        if "think" in payload:
            payload.pop("think", None)
            return _post_chat(payload)

        raise exc


def _strip_thinking(text):
    return re.sub(
        r"<think>.*?</think>",
        "",
        str(text or ""),
        flags=re.DOTALL | re.IGNORECASE,
    ).strip()


def _parse_json(text):
    text = _strip_thinking(text)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    first = text.find("{")
    last = text.rfind("}")

    if first != -1 and last > first:
        try:
            return json.loads(text[first:last + 1])
        except json.JSONDecodeError:
            pass

    return None


def normalize_verdict(value):
    key = (
        str(value or "")
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )

    return _VERDICT_LOOKUP.get(key)


def _normalize_confidence(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0

    if number > 1.0:
        number = number / 100.0

    return max(0.0, min(1.0, number))


def _ollama_metrics(response):
    keys = (
        "total_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_duration",
        "eval_count",
        "eval_duration",
    )

    return {key: response.get(key) for key in keys if key in response}


# ==========================================================
# PUBLIC API
# ==========================================================

def validate_threat(context):
    started = time.perf_counter()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Below is network traffic described by IP, port and, when "
                "available, the observed HTTP request. Analyze whether it "
                "is malicious.\n\nEvidence:\n"
                + json.dumps(context, ensure_ascii=False, default=str)
            ),
        },
    ]

    try:
        response = _chat(messages)

    except Exception as exc:
        return {
            "status": "error",
            "reason": "ollama_request_failed",
            "error": str(exc),
            "error_type": type(exc).__name__,
            "verdict": None,
            "confidence": 0.0,
            "model": VALIDATOR_MODEL,
            "timing": {"seconds": time.perf_counter() - started},
        }

    elapsed = time.perf_counter() - started
    content = (response.get("message") or {}).get("content", "")
    parsed = _parse_json(content)

    base = {
        "model": VALIDATOR_MODEL,
        "timing": {"seconds": elapsed},
        "ollama_metrics": _ollama_metrics(response),
        "raw_response": content[:2000],
    }

    if not isinstance(parsed, dict):
        return {
            **base,
            "status": "invalid_response",
            "reason": "response_not_json",
            "verdict": None,
            "confidence": 0.0,
        }

    verdict = normalize_verdict(parsed.get("verdict"))

    if verdict is None:
        return {
            **base,
            "status": "invalid_response",
            "reason": "unknown_verdict",
            "verdict": None,
            "confidence": 0.0,
            "parsed": parsed,
        }

    indicators = parsed.get("malicious_indicators") or []

    if isinstance(indicators, str):
        indicators = [indicators]

    return {
        **base,
        "status": "completed",
        "reason": "validated",
        "verdict": verdict,
        "confidence": _normalize_confidence(parsed.get("confidence")),
        "benign_explanation": str(parsed.get("benign_explanation") or ""),
        "malicious_indicators": [str(item) for item in indicators][:8],
        "reasoning": str(parsed.get("reasoning") or ""),
        "recommended_next_step": str(parsed.get("recommended_next_step") or ""),
    }


def is_attack_verdict(validation, suspicious_min_confidence=0.80):
    """MITRE'ye geçiş kapısı: Malicious veya yüksek güvenli Suspicious."""
    if not isinstance(validation, dict):
        return False

    if validation.get("status") != "completed":
        return False

    verdict = validation.get("verdict")

    if verdict == "Malicious":
        return True

    return (
        verdict == "Suspicious"
        and float(validation.get("confidence") or 0.0)
        >= suspicious_min_confidence
    )


def warm_up_validator():
    started = time.perf_counter()

    _chat(
        [{"role": "user", "content": "ok"}],
        num_predict=1,
        json_format=False,
    )

    return time.perf_counter() - started