import json
import re
import time

import requests

try:
    from .mitre_retriever import MitreRetriever
except ImportError:
    from mitre_retriever import MitreRetriever
from mitre_multi_retriever import retrieve_candidates

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL_NAME = "qwen3:8b"
CANDIDATE_COUNT = 8
MAX_TECHNIQUES = 3

RETRIEVER = MitreRetriever()


def warm_up():
    """Load the model into memory once, so load time is not counted per event."""
    started = time.perf_counter()
    requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL_NAME,
            "prompt": "ok",
            "stream": False,
            "think": False,
            "keep_alive": "30m",
            "options": {"num_predict": 1},
        },
        timeout=180,
    ).raise_for_status()
    return time.perf_counter() - started


def _compact_candidate(rank, candidate):
    item = {
        "rank": rank,
        "id": candidate["id"],
        "name": candidate["name"],
        "tactics": candidate.get("tactics", []),
    }
    notes = [
        r for r in candidate.get("evidence_reasons", [])
        if "not supported" in r or "conflicts" in r
    ]
    if notes:
        item["note"] = "; ".join(notes)
    return item


def _candidate_lines(candidates):
    lines = []
    for c in candidates:
        line = c["id"] + " | " + c["name"] + " | " + ",".join(c["tactics"])
        if c.get("note"):
            line += " | WARNING: " + c["note"]
        lines.append(line)
    return "\n".join(lines)


def _build_prompt(evidence, candidates):
    evidence_json = json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))

    return f"""/no_think
You are a senior MITRE ATT&CK analyst. Decide which techniques the SOC evidence supports.

Rules:
- Choose from CANDIDATES only, using the exact id.
- Select every technique the evidence directly supports, up to {MAX_TECHNIQUES}.
- Port usage or SMB traffic alone is not proof of a specific technique.
- Do not choose a lateral movement technique unless the evidence shows authentication, file access or remote execution. Connection counts alone indicate discovery.
- Do not infer tool or file transfer without byte or file evidence.
- Treat a WARNING on a candidate as a reason to avoid it.
- Keep each reason under 12 words.
- Return JSON only.

SOC EVIDENCE:
{evidence_json}

CANDIDATES (id | name | tactics):
{_candidate_lines(candidates)}

OUTPUT:
{{"techniques":[{{"id":"","confidence":0.0,"reason":""}}]}}"""


def _parse_json(text):
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.S)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
    return {"techniques": [], "parse_error": text[:300]}


def analyze_mitre(attack_label, confidence, behavioral_findings, host_state=None,
                  candidate_count=CANDIDATE_COUNT):
    # host_state is accepted for compatibility but not sent: its values
    # are already present in behavioral_findings and only add prompt tokens.
    total_start = time.perf_counter()

    # Stage 1: local retrieval (milliseconds)
    started = time.perf_counter()
    retrieval = retrieve_candidates(
        retriever=RETRIEVER,
        behavioral_findings=behavioral_findings,
        per_query_k=10,
        final_k=candidate_count,
    )
    retrieval_seconds = time.perf_counter() - started

    candidates = [_compact_candidate(i, c) for i, c in enumerate(retrieval["candidates"], 1)]
    allowed = {c["id"] for c in candidates}

    evidence = {
        "attack_label": attack_label,
        "confidence": confidence,
        "behavioral_findings": behavioral_findings,
    }

    # Stage 2: one local Qwen call
    started = time.perf_counter()
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL_NAME,
            "prompt": _build_prompt(evidence, candidates),
            "stream": False,
            "think": False,
            "format": "json",
            "keep_alive": "30m",
            "options": {"temperature": 0, "num_predict": 200, "num_ctx": 2048},
        },
        timeout=120,
    )
    response.raise_for_status()
    body = response.json()
    qwen_seconds = time.perf_counter() - started

    result = _parse_json(body.get("response", ""))

    # Guard: Qwen may only pick from the supplied candidates.
    valid, rejected = [], []
    for item in result.get("techniques", []):
        if isinstance(item, dict) and item.get("id") in allowed:
            valid.append(item)
        else:
            rejected.append(item)
    result["techniques"] = valid[:MAX_TECHNIQUES]
    if rejected:
        result["rejected_non_candidate"] = rejected

    name_by_id = {c["id"]: c["name"] for c in candidates}
    for item in result["techniques"]:
        item["name"] = name_by_id.get(item["id"], "")

    return {
        "result": result,
        "candidates": candidates,
        "retrieval_seconds": retrieval_seconds,
        "qwen_seconds": qwen_seconds,
        "elapsed_seconds": time.perf_counter() - total_start,
        "ollama_metrics": {
            "prompt_eval_count": body.get("prompt_eval_count"),
            "eval_count": body.get("eval_count"),
            "prompt_eval_duration_ns": body.get("prompt_eval_duration"),
            "eval_duration_ns": body.get("eval_duration"),
            "load_duration_ns": body.get("load_duration"),
            "total_duration_ns": body.get("total_duration"),
        },
    }
