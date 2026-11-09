# mitre_runner.py
"""
MITRE eşleme katmanı (artık KARAR VERİCİ DEĞİL, aksiyon/açıklama katmanı).

- live_soc.py içindeki MITRE kodu buraya taşındı; soc_api.py de dashboard
  butonu için aynı fonksiyonu kullanır.
- mitre_agent LAZY import edilir: MITRE hiç gerekmezse retriever / ATT&CK
  verisi belleğe yüklenmez.
- Çıktı network_mitre ile sensörün görebildiği tekniklere filtrelenir.
"""

import functools
import json
import os
import re
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from pathlib import Path

import numpy as np

from network_mitre import filter_mitre_analysis

BASE_DIR = Path(__file__).resolve().parent
MITRE_DIR = BASE_DIR / "mitre"

for _path in (BASE_DIR, MITRE_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

MITRE_CANDIDATE_COUNT = 8

# os.chdir süreç geneli olduğu için (soc_api çok thread'li) kilitli.
_mitre_lock = threading.RLock()
_mitre_functions = {}


# ==========================================================
# GENERAL HELPERS
# ==========================================================

@contextmanager
def working_directory(path):
    """
    mitre/ kodu '../cache/...' gibi CWD'ye göre göreli yollar kullanıyor.
    CWD geçici olarak mitre/ yapılır, sonra geri alınır.
    """
    previous = Path.cwd()
    os.chdir(str(path))

    try:
        yield
    finally:
        os.chdir(str(previous))


def safe_json_value(value):
    if isinstance(value, dict):
        return {str(key): safe_json_value(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [safe_json_value(item) for item in value]

    if isinstance(value, np.ndarray):
        return [safe_json_value(item) for item in value.tolist()]

    if isinstance(value, np.generic):
        return value.item()

    if isinstance(value, Path):
        return str(value)

    return value


def decode_json_if_possible(value):
    if not isinstance(value, str):
        return value

    text = value.strip()

    if not text:
        return value

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    first_brace = text.find("{")
    last_brace = text.rfind("}")

    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace:last_brace + 1])
        except json.JSONDecodeError:
            pass

    return value


# ==========================================================
# LAZY MITRE AGENT
# ==========================================================

def _load_mitre_functions():
    with _mitre_lock:
        if _mitre_functions:
            return _mitre_functions

        print("Loading MITRE agent (lazy)...")

        # mitre_agent import edilirken MitreRetriever() oluşuyor ve
        # ../cache/attack_enterprise.json okunuyor -> CWD mitre/ olmalı.
        with working_directory(MITRE_DIR):
            from mitre.mitre_agent import (
                analyze_mitre as _analyze_mitre,
                warm_up as _warm_up,
            )

        def _wrap(function):
            @functools.wraps(function)
            def wrapper(*args, **kwargs):
                with _mitre_lock:
                    with working_directory(MITRE_DIR):
                        return function(*args, **kwargs)
            return wrapper

        _mitre_functions["analyze_mitre"] = _wrap(_analyze_mitre)
        _mitre_functions["warm_up"] = _wrap(_warm_up)

        return _mitre_functions


def warm_up_mitre_engine():
    return _load_mitre_functions()["warm_up"]()


# ==========================================================
# MITRE RESULT NORMALIZATION
# ==========================================================

def normalize_technique(technique):
    technique = decode_json_if_possible(technique)

    if isinstance(technique, str):
        match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", technique, flags=re.IGNORECASE)

        if not match:
            return None

        return {
            "id": match.group(0).upper(),
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
        technique.get("score", technique.get("probability", 0.0)),
    )

    reason = (
        technique.get("reason")
        or technique.get("rationale")
        or technique.get("explanation")
        or ""
    )

    if not technique_id:
        return None

    technique_id = str(technique_id).strip().upper()

    if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
        return None

    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0

    if 1.0 < confidence <= 100.0:
        confidence = confidence / 100.0

    confidence = max(0.0, min(1.0, confidence))

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
        normalized = [t for t in (normalize_technique(i) for i in value) if t]

        if normalized:
            return normalized

        for item in value:
            nested = find_technique_list(item, depth + 1)
            if nested:
                return nested

        return []

    if not isinstance(value, dict):
        return []

    for key in (
        "techniques",
        "mitre_techniques",
        "attack_techniques",
        "selected_techniques",
        "matches",
    ):
        if key in value:
            nested = find_technique_list(value[key], depth + 1)
            if nested:
                return nested

    for key in (
        "result",
        "response",
        "output",
        "analysis",
        "parsed_result",
        "data",
        "message",
        "content",
    ):
        if key in value:
            nested = find_technique_list(value[key], depth + 1)
            if nested:
                return nested

    direct = normalize_technique(value)

    return [direct] if direct is not None else []


def deduplicate_techniques(techniques):
    unique = {}

    for technique in techniques:
        technique_id = technique.get("id")

        if not technique_id:
            continue

        existing = unique.get(technique_id)

        if existing is None or technique.get("confidence", 0.0) > existing.get("confidence", 0.0):
            unique[technique_id] = technique

    return list(unique.values())


def normalize_mitre_result(mitre_output):
    decoded = decode_json_if_possible(mitre_output)
    return {"techniques": deduplicate_techniques(find_technique_list(decoded))}


def get_mitre_candidates(mitre_output):
    if not isinstance(mitre_output, dict):
        return []

    candidates = decode_json_if_possible(mitre_output.get("candidates", []))

    if isinstance(candidates, list):
        return candidates

    return [candidates] if candidates else []


def skipped_mitre(status, reason, message):
    """MITRE çağrılmadı. status: skipped | deferred."""
    return {
        "status": status,
        "reason": reason,
        "message": message,
        "result": {"techniques": []},
        "candidates": [],
        "timing": {
            "retrieval_seconds": 0.0,
            "qwen_seconds": 0.0,
            "total_seconds": 0.0,
        },
    }


# ==========================================================
# MITRE ANALYSIS (yalnızca saldırı doğrulandıktan sonra)
# ==========================================================

def run_mitre_analysis(
        layer1_label,
        layer1_confidence,
        behavioral_findings,
        correlation_data,
        flow_info=None,
        layer2_result=None,
        http_evidence=None,
        activity=None,
        validation=None,
        candidate_count=MITRE_CANDIDATE_COUNT,
        debug=False,
):
    flow_info = flow_info if isinstance(flow_info, dict) else {}
    layer2_result = layer2_result if isinstance(layer2_result, dict) else {}
    http_evidence = http_evidence if isinstance(http_evidence, dict) else {}
    activity = activity if isinstance(activity, dict) else {}
    validation = validation if isinstance(validation, dict) else {}
    correlation_data = correlation_data if isinstance(correlation_data, dict) else {}

    enriched_findings = [
        dict(item) for item in (behavioral_findings or []) if isinstance(item, dict)
    ]

    l2_status = str(layer2_result.get("status") or "").lower()
    l2_label = str(layer2_result.get("label") or "").strip().lower().replace("-", "_")
    l2_conf = float(layer2_result.get("confidence") or 0.0)

    if l2_status == "classified" and l2_label not in {"", "benign", "normal", "none", "unknown"}:
        enriched_findings.append(
            {
                "behavior": l2_label,
                "confidence": max(l2_conf, 0.90),
                "score": int(max(l2_conf, 0.90) * 100),
                "mitre": "T1190",
                "evidence": {
                    "layer2_label": l2_label,
                    "http_method": http_evidence.get("method"),
                    "http_path": http_evidence.get("path"),
                    "http_query": http_evidence.get("query"),
                    "validator_indicators": validation.get("malicious_indicators") or [],
                },
            }
        )

    if not enriched_findings:
        enriched_findings = [
            {
                "behavior": str(layer1_label).lower().replace(" ", "_"),
                "confidence": float(layer1_confidence),
                "score": int(float(layer1_confidence) * 100),
                "evidence": {
                    "validator_indicators": validation.get("malicious_indicators") or [],
                    "http_path": http_evidence.get("path"),
                    "http_query": http_evidence.get("query"),
                },
            }
        ]

    effective_label = (
        l2_label
        if (l2_status == "classified" and l2_label not in {"", "benign", "normal", "none", "unknown"})
        else str(layer1_label)
    )

    started = time.perf_counter()

    try:
        analyze_mitre = _load_mitre_functions()["analyze_mitre"]

        mitre_output = analyze_mitre(
            attack_label=effective_label,
            confidence=max(float(layer1_confidence), l2_conf),
            behavioral_findings=enriched_findings,
            host_state={
                "correlation_risk_score": correlation_data.get("risk_score", 0),
                "correlation_severity": correlation_data.get("severity", "informational"),
                "suspicious_activity": correlation_data.get("suspicious_activity", False),

                # Sensör kapsamı: yalnızca ağ akışı
                "sensor_visibility": "network_flow_only",

                # Threat Validator kararı
                "validator_verdict": validation.get("verdict"),
                "validator_confidence": validation.get("confidence"),
                "validator_indicators": validation.get("malicious_indicators"),
                "validator_reasoning": validation.get("reasoning"),

                # Flow evidence
                "src_ip": flow_info.get("src_ip"),
                "dst_ip": flow_info.get("dst_ip"),
                "src_port": flow_info.get("src_port"),
                "dst_port": flow_info.get("dst_port"),
                "protocol": flow_info.get("protocol"),
                "flow_timestamp": flow_info.get("timestamp"),

                # Layer 2 evidence
                "layer2_label": layer2_result.get("label"),
                "layer2_confidence": layer2_result.get("confidence"),
                "layer2_status": layer2_result.get("status"),

                # HTTP evidence
                "http_method": http_evidence.get("method"),
                "http_path": http_evidence.get("path"),
                "http_has_query": http_evidence.get("has_query", False),
                "http_has_body": http_evidence.get("has_body", False),
                "http_request_count": http_evidence.get("request_count", 0),

                # Source activity
                "activity_window_seconds": activity.get("window_seconds"),
                "recent_flow_count": activity.get("flow_count", 0),
                "unique_dst_ips": activity.get("unique_dst_ips", 0),
                "unique_dst_ports": activity.get("unique_dst_ports", 0),
            },
            candidate_count=candidate_count,
        )

        elapsed = time.perf_counter() - started

        decoded_output = decode_json_if_possible(mitre_output or {})
        normalized_result = normalize_mitre_result(decoded_output)
        candidates = get_mitre_candidates(decoded_output)
        techniques = normalized_result.get("techniques", [])

        if debug:
            print("\n========== MITRE RAW OUTPUT ==========")
            try:
                print(json.dumps(safe_json_value(decoded_output), indent=2, ensure_ascii=False))
            except Exception:
                print(repr(decoded_output))
            print("MITRE CANDIDATE COUNT ->", len(candidates))
            print("MITRE TECHNIQUE COUNT ->", len(techniques))
            print("======================================\n")

        if techniques:
            status, status_reason, message = "completed", "techniques_selected", None
        elif not candidates:
            status, status_reason = "insufficient_evidence", "no_candidates"
            message = "MITRE retriever returned no candidates."
        else:
            status, status_reason = "insufficient_evidence", "candidates_not_specific_enough"
            message = (
                "MITRE candidates were retrieved, but the available "
                "network-flow evidence was not specific enough to "
                "select a technique reliably."
            )

        output = decoded_output if isinstance(decoded_output, dict) else {}

        response = {
            "status": status,
            "reason": status_reason,
            "result": normalized_result,
            "candidates": candidates,
            "timing": {
                "retrieval_seconds": float(output.get("retrieval_seconds", 0.0) or 0.0),
                "qwen_seconds": float(output.get("qwen_seconds", 0.0) or 0.0),
                "total_seconds": float(output.get("elapsed_seconds", elapsed) or elapsed),
            },
            "ollama_metrics": output.get("ollama_metrics", {}),
            "raw_output": safe_json_value(decoded_output),
        }

        if message:
            response["message"] = message

        filtered = filter_mitre_analysis(
            response,
            has_payload_evidence=bool(layer2_result or http_evidence),
        )

        # Doğrulanmış saldırıda retriever/LLM teknik seçemediyse kanıta dayalı deterministik teknik ata
        kept_techniques = (filtered.get("result") or {}).get("techniques") or []
        if not kept_techniques and validation.get("verdict") in ("Malicious", "Suspicious"):
            fallback_tech = None
            if l2_status == "classified" and l2_label in {
                "sql_injection", "xss", "path_traversal", "command_injection", "web_attack"
            }:
                fallback_tech = {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "confidence": round(max(l2_conf, float(validation.get("confidence") or 0.90)), 2),
                    "visibility": "content_visible",
                    "reason": f"HTTP {l2_label} exploit payload confirmed in request",
                }
            elif any(
                isinstance(b, dict) and b.get("behavior") == "http_credential_brute_force"
                for b in enriched_findings
            ):
                fallback_tech = {
                    "id": "T1110.001",
                    "name": "Brute Force: Password Guessing",
                    "confidence": round(float(validation.get("confidence") or 0.92), 2),
                    "visibility": "content_visible",
                    "reason": "Repeated failed HTTP authentication / credential guessing attempts detected",
                }
            elif any(
                isinstance(b, dict) and b.get("behavior") == "multi_port_service_scan"
                for b in enriched_findings
            ):
                fallback_tech = {
                    "id": "T1046",
                    "name": "Network Service Discovery",
                    "confidence": round(float(validation.get("confidence") or 0.90), 2),
                    "visibility": "flow_visible",
                    "reason": "Multi-port TCP service discovery scan across multiple target ports",
                }
            elif any(
                isinstance(b, dict) and b.get("behavior") == "http_parameter_enumeration"
                for b in enriched_findings
            ):
                fallback_tech = {
                    "id": "T1595.002",
                    "name": "Active Scanning: Vulnerability Scanning",
                    "confidence": round(float(validation.get("confidence") or 0.88), 2),
                    "visibility": "flow_visible",
                    "reason": "Sequential HTTP endpoint parameter enumeration detected",
                }
            elif str(layer1_label).strip().lower() in {"brute force", "password"}:
                fallback_tech = {
                    "id": "T1110",
                    "name": "Brute Force",
                    "confidence": round(float(validation.get("confidence") or 0.85), 2),
                    "visibility": "flow_visible",
                    "reason": "Repeated authentication or credential guessing traffic",
                }
            elif str(layer1_label).strip().lower() in {"dos", "ddos"}:
                fallback_tech = {
                    "id": "T1499",
                    "name": "Endpoint Denial of Service",
                    "confidence": round(float(validation.get("confidence") or 0.85), 2),
                    "visibility": "flow_visible",
                    "reason": "High-rate denial of service traffic pattern",
                }
            elif str(layer1_label).strip().lower() == "reconnaissance":
                fallback_tech = {
                    "id": "T1595",
                    "name": "Active Scanning",
                    "confidence": round(float(validation.get("confidence") or 0.85), 2),
                    "visibility": "flow_visible",
                    "reason": "Active network probing / reconnaissance traffic",
                }

            if fallback_tech is not None:
                filtered["status"] = "completed"
                filtered["reason"] = "evidence_backed_mapping"
                filtered.pop("message", None)
                filtered["result"] = {"techniques": [fallback_tech]}
                if not filtered.get("candidates"):
                    filtered["candidates"] = [
                        {
                            "rank": 1,
                            "id": fallback_tech["id"],
                            "name": fallback_tech["name"],
                            "tactics": ["initial-access" if fallback_tech["id"] == "T1190" else "reconnaissance"],
                        }
                    ]

        return filtered

    except Exception as exc:
        elapsed = time.perf_counter() - started

        print("MITRE ANALYSIS FAILED ->", repr(exc))
        traceback.print_exc()

        return {
            "status": "error",
            "reason": "exception",
            "error": str(exc),
            "error_type": type(exc).__name__,
            "result": {"techniques": []},
            "candidates": [],
            "timing": {
                "retrieval_seconds": 0.0,
                "qwen_seconds": 0.0,
                "total_seconds": elapsed,
            },
        }


def run_mitre_from_alert(metadata, validation=None):
    """soc_api butonu için: kayıtlı alert JSON'undan MITRE çalıştırır."""
    flow_info = {
        "src_ip": metadata.get("src_ip"),
        "dst_ip": metadata.get("dst_ip"),
        "src_port": metadata.get("src_port"),
        "dst_port": metadata.get("dst_port"),
        "protocol": metadata.get("protocol"),
        "timestamp": metadata.get("timestamp"),
    }

    return run_mitre_analysis(
        layer1_label=metadata.get("label"),
        layer1_confidence=float(metadata.get("confidence") or 0.0),
        behavioral_findings=metadata.get("behavioral_findings") or [],
        correlation_data=metadata.get("correlation_summary") or {},
        flow_info=flow_info,
        layer2_result=metadata.get("layer2"),
        http_evidence=metadata.get("http_evidence"),
        activity=metadata.get("source_activity"),
        validation=validation or metadata.get("threat_validation"),
    )
