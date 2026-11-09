# action_agent.py
"""
Qwen3:8b SOAR / Active Response Agent.

Doğrulanmış tehditleri (Malicious / yüksek güvenli Suspicious) ve eşleşen
MITRE ATT&CK tekniklerini girdi olarak alır; Qwen3:8b modeli ile uygun
savunma araçlarını (Tools) seçer ve lokalde aksiyon alır:
  - block_ip             : Saldırgan IP'yi güvenlik duvarı karantina listesine ekler
  - add_waf_rule         : HTTP exploit payload'unu (SQLi/XSS/Traversal) WAF filtresine yazar
  - rate_limit_source    : DoS / Flood / Tarama yapan kaynağa hız sınırı uygular
  - isolate_endpoint     : Hedef makinede şüpheli C2 / sızıntı oturumunu karantinaya alır
  - create_incident_case : SOC vaka kaydı (Incident Ticket) açar ve ledger'a kaydeder
"""

import json
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import unquote

BASE_DIR = Path(__file__).resolve().parent
ALERTS_DIR = BASE_DIR / "alerts"

ACTIONS_LEDGER_FILE = ALERTS_DIR / "actions_ledger.json"
WAF_RULES_FILE = ALERTS_DIR / "waf_rules.json"
BLOCKED_IPS_FILE = ALERTS_DIR / "blocked_ips.json"
RATE_LIMITS_FILE = ALERTS_DIR / "rate_limits.json"
INCIDENTS_FILE = ALERTS_DIR / "incidents.json"

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
AGENT_MODEL = "qwen3:8b"
AGENT_TIMEOUT = 90
AGENT_KEEP_ALIVE = "30m"
AGENT_NUM_CTX = 3072
AGENT_NUM_PREDICT = 320
AGENT_DISABLE_THINKING = True

# True iken macOS pfctl firewall komutunu simüle eder ve JSON kurallarına yazar (güvenli mod).
# Gerçekten macOS pfctl tablosuna IP eklemek için False yapılabilir.
DRY_RUN_FIREWALL = True

# Kendinizi veya yerel ağ geçidini yanlışlıkla kilitlememek için korunan IP'ler.
PROTECTED_IPS = {"127.0.0.1", "0.0.0.0", "::1", "localhost"}

_file_lock = threading.RLock()


def _append_record(file_path: Path, record: dict):
    with _file_lock:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        records = []
        if file_path.exists():
            try:
                loaded = json.loads(file_path.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    records = loaded
            except Exception:
                records = []
        records.append(record)
        temp_path = file_path.with_name(file_path.name + ".tmp")
        temp_path.write_text(
            json.dumps(records, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        temp_path.replace(file_path)


# ==========================================================
# 1. SOAR TOOLS (Aksiyon Fonksiyonları)
# ==========================================================

def tool_block_ip(ip: str, duration_minutes: int = 60, reason: str = "", mitre_id: str = "") -> dict:
    """Saldırgan IP adresini güvenlik duvarı (pfctl) ve SOC blok listesine ekler."""
    ip_str = str(ip or "").strip()
    if not ip_str:
        return {"tool": "block_ip", "status": "skipped", "reason": "empty_ip"}

    try:
        duration_minutes = max(5, min(10080, int(duration_minutes)))
    except (TypeError, ValueError):
        duration_minutes = 60

    pf_cmd = ["sudo", "pfctl", "-t", "mitre_soc_blocklist", "-T", "add", ip_str]
    mode = "simulated"

    if ip_str in PROTECTED_IPS:
        mode = "protected_whitelist_simulated"
    elif not DRY_RUN_FIREWALL:
        try:
            proc = subprocess.run(pf_cmd, capture_output=True, text=True, timeout=5)
            mode = "executed_pfctl" if proc.returncode == 0 else "pfctl_fallback_logged"
        except Exception:
            mode = "pfctl_fallback_logged"

    entry = {
        "timestamp": time.time(),
        "tool": "block_ip",
        "status": "completed",
        "execution_mode": mode,
        "target_ip": ip_str,
        "duration_minutes": duration_minutes,
        "mitre_id": str(mitre_id or ""),
        "command": " ".join(pf_cmd),
        "reason": str(reason or "Confirmed hostile activity"),
    }
    _append_record(BLOCKED_IPS_FILE, entry)
    return entry


def tool_add_waf_rule(payload_pattern: str, target_port: int = 80, mitre_id: str = "T1190", reason: str = "") -> dict:
    """HTTP saldırılarında (SQLi, XSS, Traversal) zararlı deseni WAF kural listesine ekler."""
    raw_pattern = str(payload_pattern or "").strip()
    decoded_pattern = unquote(raw_pattern) if raw_pattern else ""

    try:
        target_port = int(target_port or 80)
    except (TypeError, ValueError):
        target_port = 80

    entry = {
        "timestamp": time.time(),
        "tool": "add_waf_rule",
        "status": "completed",
        "execution_mode": "active_rule_deployed",
        "target_port": target_port,
        "blocked_pattern_raw": raw_pattern[:300],
        "blocked_pattern_decoded": decoded_pattern[:300],
        "mitre_id": str(mitre_id or "T1190"),
        "reason": str(reason or "Malicious HTTP payload signature"),
    }
    _append_record(WAF_RULES_FILE, entry)
    return entry


def tool_rate_limit_source(ip: str, dst_port: int = 0, max_pps: int = 30, reason: str = "") -> dict:
    """DoS, Flood veya hızlı tarama/enumeration yapan kaynağa hız sınırı uygular."""
    ip_str = str(ip or "").strip()
    try:
        dst_port = int(dst_port or 0)
    except (TypeError, ValueError):
        dst_port = 0
    try:
        max_pps = max(1, min(1000, int(max_pps)))
    except (TypeError, ValueError):
        max_pps = 30

    entry = {
        "timestamp": time.time(),
        "tool": "rate_limit_source",
        "status": "completed",
        "execution_mode": "active_throttling",
        "target_ip": ip_str,
        "dst_port": dst_port,
        "max_pps": max_pps,
        "reason": str(reason or "High packet/request rate detected"),
    }
    _append_record(RATE_LIMITS_FILE, entry)
    return entry


def tool_isolate_endpoint(host_ip: str, peer_ip: str = "", reason: str = "") -> dict:
    """C2 iletişimi veya veri sızıntısı (Exfiltration) tespit edilen oturumu izole eder."""
    entry = {
        "timestamp": time.time(),
        "tool": "isolate_endpoint",
        "status": "completed",
        "execution_mode": "session_quarantined",
        "host_ip": str(host_ip or ""),
        "peer_ip": str(peer_ip or ""),
        "reason": str(reason or "Suspicious C2 or exfiltration channel"),
    }
    return entry


def tool_create_incident_case(severity: str = "high", mitre_ids: list = None, summary: str = "", src_ip: str = "") -> dict:
    """Doğrulanmış saldırı için SOC Vaka Kaydı (Incident Case) oluşturur."""
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    mitre_list = [str(x) for x in (mitre_ids or []) if x]

    summary_text = str(summary or "Automated SOAR incident created.")
    entry = {
        "timestamp": time.time(),
        "tool": "create_incident_case",
        "status": "completed",
        "execution_mode": "ticket_created",
        "severity": str(severity or "high").lower(),
        "src_ip": str(src_ip or ""),
        "mitre_ids": mitre_list,
        "summary": summary_text,
        "reason": summary_text,
    }
    _append_record(INCIDENTS_FILE, entry)
    return entry


AVAILABLE_TOOLS = {
    "block_ip": tool_block_ip,
    "add_waf_rule": tool_add_waf_rule,
    "rate_limit_source": tool_rate_limit_source,
    "isolate_endpoint": tool_isolate_endpoint,
    "create_incident_case": tool_create_incident_case,
}


# ==========================================================
# 2. AGENT SYSTEM PROMPT & OLLAMA CALL
# ==========================================================

AGENT_SYSTEM_PROMPT = """You are an autonomous SOAR (Security Orchestration, Automation, and Response) Agent in a live SOC.
A network threat has been validated and mapped to MITRE ATT&CK techniques.
Your task is to select and parameterize the exact defensive tools to neutralize the threat.

Available Tools:
1. "block_ip": {"ip": "<src_ip>", "duration_minutes": 120, "mitre_id": "<Txxxx>", "reason": "<why>"}
   -> Use for SQL Injection / Web Exploits (T1190), Brute Force (T1110), Active Scanning / Reconnaissance (T1595, T1046), or C2 traffic.
2. "add_waf_rule": {"payload_pattern": "<exact malicious query/uri/body substring>", "target_port": <dst_port>, "mitre_id": "T1190", "reason": "<why>"}
   -> MUST use whenever `http_evidence` or `malicious_indicators` contains SQL injection (e.g. admin'--, admin%27--, UNION, OR 1=1), XSS, path traversal, or web exploit strings.
3. "rate_limit_source": {"ip": "<src_ip>", "dst_port": <dst_port>, "max_pps": 20, "reason": "<why>"}
   -> Use for DoS/Flood (T1498, T1499), rapid API enumeration (e.g. /api/users?id=...), or port scanning.
4. "isolate_endpoint": {"host_ip": "<dst_ip>", "peer_ip": "<src_ip>", "reason": "<why>"}
   -> Use only for Exfiltration (T1041) or C2 (T1071) where an internal host is compromised.
5. "create_incident_case": {"severity": "high" | "critical", "mitre_ids": ["<Txxxx>"], "src_ip": "<src_ip>", "summary": "<concise incident summary>"}
   -> ALWAYS include this tool call to log the SOC incident case.

Return ONLY a valid JSON object with this exact schema:
{
  "mitre_mitigation_id": "M1030 | M1036 | M1050 | M1037",
  "mitigation_name": "Network Intrusion Prevention / Filter Network Traffic / Exploit Protection",
  "action_plan_summary": "1-2 sentences explaining the defensive response.",
  "tool_calls": [
    {
      "tool_name": "block_ip",
      "arguments": {"ip": "...", "duration_minutes": 120, "mitre_id": "...", "reason": "..."}
    }
  ]
}"""


def _strip_thinking(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", str(text or ""), flags=re.DOTALL | re.IGNORECASE).strip()


def _parse_json(text: str):
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


def _chat_agent(messages):
    payload = {
        "model": AGENT_MODEL,
        "messages": messages,
        "stream": False,
        "keep_alive": AGENT_KEEP_ALIVE,
        "format": "json",
        "options": {
            "temperature": 0,
            "num_predict": AGENT_NUM_PREDICT,
            "num_ctx": AGENT_NUM_CTX,
        },
    }
    if AGENT_DISABLE_THINKING:
        payload["think"] = False

    def _post(body):
        req = urllib.request.Request(
            OLLAMA_URL,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=AGENT_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))

    try:
        return _post(payload)
    except urllib.error.HTTPError:
        if "think" in payload:
            payload.pop("think", None)
            return _post(payload)
        raise


def _deterministic_fallback_plan(agent_input: dict) -> dict:
    """LLM yanıtı ayrıştırılamazsa kanıta dayalı deterministik SOAR planı üretir."""
    src_ip = agent_input.get("src_ip") or ""
    dst_port = agent_input.get("dst_port") or 80
    techniques = agent_input.get("mitre_techniques") or []
    tech_ids = [t.get("id") for t in techniques if isinstance(t, dict) and t.get("id")]
    primary_tech = tech_ids[0] if tech_ids else "T1190"
    http_ev = agent_input.get("http_evidence") or {}
    indicators = agent_input.get("malicious_indicators") or []

    calls = []
    if src_ip:
        calls.append({
            "tool_name": "block_ip",
            "arguments": {
                "ip": src_ip,
                "duration_minutes": 120,
                "mitre_id": primary_tech,
                "reason": f"Confirmed {agent_input.get('validator_verdict')} activity ({primary_tech})",
            },
        })

    query_or_uri = http_ev.get("query") or http_ev.get("path") or (indicators[0] if indicators else "")
    if query_or_uri:
        calls.append({
            "tool_name": "add_waf_rule",
            "arguments": {
                "payload_pattern": str(query_or_uri),
                "target_port": dst_port,
                "mitre_id": primary_tech,
                "reason": "Blocked malicious HTTP request pattern",
            },
        })

    calls.append({
        "tool_name": "create_incident_case",
        "arguments": {
            "severity": "high",
            "mitre_ids": tech_ids or [primary_tech],
            "src_ip": src_ip,
            "summary": f"Automated response executed against {src_ip} on port {dst_port}.",
        },
    })

    return {
        "mitre_mitigation_id": "M1030",
        "mitigation_name": "Network Intrusion Prevention",
        "action_plan_summary": "Executed automated IP quarantine, payload filtering, and incident logging.",
        "tool_calls": calls,
    }


def skipped_action(status: str, reason: str, message: str) -> dict:
    return {
        "status": status,
        "reason": reason,
        "message": message,
        "mitre_mitigation_id": None,
        "mitigation_name": None,
        "action_plan_summary": "",
        "executed_actions": [],
        "timing": {"seconds": 0.0},
    }


def run_action_agent(metadata: dict, force: bool = False) -> dict:
    """
    Alert metadata sözlüğünü alır, Qwen3:8b SOAR Ajanı ile aksiyon planı
    oluşturur, araçları çalıştırır ve ayrıntılı raporu döndürür.
    """
    started = time.perf_counter()
    validation = metadata.get("threat_validation") or {}
    verdict = validation.get("verdict")
    val_conf = float(validation.get("confidence") or 0.0)

    is_confirmed_attack = (
        verdict == "Malicious"
        or (verdict == "Suspicious" and val_conf >= 0.80)
    )

    if not force and not is_confirmed_attack:
        return skipped_action(
            "skipped",
            "verdict_not_attack",
            f"Action Agent skipped: verdict={verdict} ({val_conf * 100:.0f}%).",
        )

    mitre_block = metadata.get("mitre_analysis") or {}
    techniques = ((mitre_block.get("result") or {}).get("techniques")) or []
    http_ev = metadata.get("http_evidence") or {}
    layer2 = metadata.get("layer2") or {}
    behavioral_findings = metadata.get("behavioral_findings") or []

    agent_input = {
        "alert_decision": metadata.get("decision"),
        "layer1_label": metadata.get("label"),
        "src_ip": metadata.get("src_ip"),
        "dst_ip": metadata.get("dst_ip"),
        "src_port": metadata.get("src_port"),
        "dst_port": metadata.get("dst_port"),
        "protocol": metadata.get("protocol"),
        "validator_verdict": verdict,
        "validator_confidence": val_conf,
        "malicious_indicators": validation.get("malicious_indicators") or [],
        "validator_reasoning": validation.get("reasoning") or "",
        "layer2_classification": {
            "status": layer2.get("status"),
            "label": layer2.get("label"),
            "confidence": layer2.get("confidence"),
        } if isinstance(layer2, dict) and layer2 else None,
        "behavioral_findings": behavioral_findings,
        "mitre_techniques": [
            {
                "id": t.get("id"),
                "name": t.get("name"),
                "confidence": t.get("confidence"),
                "reason": t.get("reason"),
            }
            for t in techniques
            if isinstance(t, dict)
        ],
        "http_evidence": {
            "method": http_ev.get("method"),
            "path": http_ev.get("path"),
            "query": http_ev.get("query"),
            "body_preview": http_ev.get("body_preview"),
            "response_summary": http_ev.get("response_summary"),
            "raw_request": str(http_ev.get("raw_request") or "")[:1200],
        } if http_ev else None,
        "source_activity": metadata.get("source_activity") or {},
    }

    messages = [
        {"role": "system", "content": AGENT_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Select and parameterize the defensive SOAR tool calls for this "
                "confirmed cyber attack:\n\n"
                + json.dumps(agent_input, ensure_ascii=False, default=str)
            ),
        },
    ]

    plan = None
    used_fallback = False

    try:
        response = _chat_agent(messages)
        content = (response.get("message") or {}).get("content", "")
        plan = _parse_json(content)
    except Exception as exc:
        print("ACTION AGENT LLM WARNING (using deterministic fallback) ->", repr(exc))

    if not isinstance(plan, dict) or not isinstance(plan.get("tool_calls"), list) or not plan.get("tool_calls"):
        plan = _deterministic_fallback_plan(agent_input)
        used_fallback = True

    executed_actions = []
    for call in plan.get("tool_calls", [])[:6]:
        if not isinstance(call, dict):
            continue
        tool_name = str(call.get("tool_name") or "").strip()
        args = call.get("arguments")
        if not isinstance(args, dict):
            args = {}

        func = AVAILABLE_TOOLS.get(tool_name)
        if func is None:
            continue

        try:
            result = func(**args)
            executed_actions.append(result)
        except Exception as exc:
            executed_actions.append({
                "tool": tool_name,
                "status": "error",
                "error": str(exc),
            })

    # Hiçbir aksiyon çalışmadıysa en azından IP bloğu ve incident kaydı oluştur
    if not executed_actions:
        fallback = _deterministic_fallback_plan(agent_input)
        for call in fallback["tool_calls"]:
            func = AVAILABLE_TOOLS.get(call["tool_name"])
            if func:
                executed_actions.append(func(**call["arguments"]))

    # Kanıta dayalı zorunlu güvenlik kontrolleri:
    # 1) Layer 2 HTTP exploit (SQLi/XSS/Traversal/CmdInj) varsa WAF kuralı kesinlikle eklensin
    executed_tools = {a.get("tool") for a in executed_actions if isinstance(a, dict)}
    l2_status = str(layer2.get("status") or "").lower() if isinstance(layer2, dict) else ""
    l2_label = str(layer2.get("label") or "").lower() if isinstance(layer2, dict) else ""
    tech_ids = [t.get("id") for t in techniques if isinstance(t, dict) and t.get("id")]
    primary_tech = tech_ids[0] if tech_ids else "T1190"

    if (
        "add_waf_rule" not in executed_tools
        and l2_status == "classified"
        and l2_label in ("sql_injection", "xss", "path_traversal", "command_injection")
    ):
        indicators = validation.get("malicious_indicators") or []
        pattern = (
            http_ev.get("query")
            or http_ev.get("body_preview")
            or (indicators[0] if indicators else "")
            or http_ev.get("path")
            or l2_label
        )
        executed_actions.append(
            tool_add_waf_rule(
                payload_pattern=str(pattern),
                target_port=metadata.get("dst_port") or 80,
                mitre_id="T1190",
                reason=f"Auto-deployed WAF signature for confirmed {l2_label}",
            )
        )
        executed_tools.add("add_waf_rule")

    # 2) HTTP Parameter Enumeration / Brute Force / Port Scan varsa hız sınırı (rate_limit_source) kesinlikle eklensin
    has_enum_behavior = any(
        isinstance(b, dict)
        and b.get("behavior") in (
            "http_parameter_enumeration",
            "http_credential_brute_force",
            "multi_port_service_scan",
            "high_connection_rate",
            "port_scan",
        )
        for b in behavioral_findings
    )
    if "rate_limit_source" not in executed_tools and has_enum_behavior and metadata.get("src_ip"):
        executed_actions.append(
            tool_rate_limit_source(
                ip=str(metadata.get("src_ip")),
                dst_port=metadata.get("dst_port") or 80,
                max_pps=15,
                reason="Auto-throttled source due to rapid HTTP parameter enumeration / scanning",
            )
        )
        executed_tools.add("rate_limit_source")

    elapsed = time.perf_counter() - started

    action_report = {
        "status": "completed",
        "reason": "fallback_playbook" if used_fallback else "qwen_soar_agent",
        "model": AGENT_MODEL,
        "mitre_mitigation_id": str(plan.get("mitre_mitigation_id") or "M1030"),
        "mitigation_name": str(plan.get("mitigation_name") or "Network Intrusion Prevention"),
        "action_plan_summary": str(plan.get("action_plan_summary") or ""),
        "executed_actions": executed_actions,
        "timing": {"seconds": round(elapsed, 2)},
        "executed_at": time.time(),
    }

    _append_record(
        ACTIONS_LEDGER_FILE,
        {
            "timestamp": time.time(),
            "src_ip": metadata.get("src_ip"),
            "dst_ip": metadata.get("dst_ip"),
            "dst_port": metadata.get("dst_port"),
            "verdict": verdict,
            "techniques": [t.get("id") for t in techniques if isinstance(t, dict)],
            "mitigation_id": action_report["mitre_mitigation_id"],
            "summary": action_report["action_plan_summary"],
            "actions_count": len(executed_actions),
            "tools": [a.get("tool") for a in executed_actions],
        },
    )

    return action_report
