# network_mitre.py
"""
Network Observable MITRE Set.

Sensörümüz yalnızca ağ akışı görür. Process Injection, LSASS dump, Registry
gibi host-only teknikler flow'dan asla kanıtlanamaz; bu modül bunları eler.

Set HARDCODE DEĞİL, ATT&CK verisinden (cache/attack_enterprise.json) türetilir:
  - Eski şema : attack-pattern.x_mitre_data_sources ("Network Traffic: ...")
  - v10-v17   : x-mitre-data-component --detects--> attack-pattern
  - v18+      : detection-strategy -> analytic -> log source -> data component
Tier:
  flow_visible    -> Network Traffic Flow / Network Connection Creation
  content_visible -> yalnızca Network Traffic Content (payload/Layer 2 gerekir)

Hiçbiri bulunamazsa küçük bir yedek liste kullanılır (source=fallback).
"""

import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_ATTACK_JSON = BASE_DIR / "cache" / "attack_enterprise.json"

FLOW_COMPONENT_PATTERN = re.compile(
    r"network\s+traffic\s+flow|network\s+connection\s+creation",
    re.IGNORECASE,
)

CONTENT_COMPONENT_PATTERN = re.compile(
    r"network\s+traffic\s+content",
    re.IGNORECASE,
)

FALLBACK_SET = {
    "T1046": "flow_visible", "T1018": "flow_visible", "T1595": "flow_visible",
    "T1021": "flow_visible", "T1110": "flow_visible", "T1071": "flow_visible",
    "T1095": "flow_visible", "T1571": "flow_visible", "T1572": "flow_visible",
    "T1090": "flow_visible", "T1041": "flow_visible", "T1048": "flow_visible",
    "T1498": "flow_visible", "T1499": "flow_visible", "T1557": "flow_visible",
    "T1133": "flow_visible", "T1219": "flow_visible", "T1568": "flow_visible",
    "T1573": "flow_visible", "T1029": "flow_visible", "T1030": "flow_visible",
    "T1105": "content_visible", "T1567": "content_visible",
    "T1190": "content_visible", "T1210": "content_visible",
    "T1189": "content_visible", "T1001": "content_visible",
    "T1132": "content_visible",
}

_TIER_RANK = {"content_visible": 1, "flow_visible": 2}

_cache = {"path": None, "set": None, "source": None}


def _attack_id(obj):
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]).upper()
    return None


def _tier_for(name):
    if FLOW_COMPONENT_PATTERN.search(name or ""):
        return "flow_visible"
    if CONTENT_COMPONENT_PATTERN.search(name or ""):
        return "content_visible"
    return None


def _merge(result, technique_id, tier):
    if not technique_id or not tier:
        return
    current = result.get(technique_id)
    if current is None or _TIER_RANK[tier] > _TIER_RANK[current]:
        result[technique_id] = tier


def derive_from_attack_json(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        bundle = json.load(handle)

    objects = bundle.get("objects", []) if isinstance(bundle, dict) else bundle
    by_id = {obj.get("id"): obj for obj in objects if isinstance(obj, dict)}

    patterns = {
        obj["id"]: _attack_id(obj)
        for obj in objects
        if isinstance(obj, dict)
        and obj.get("type") == "attack-pattern"
        and not obj.get("revoked")
        and not obj.get("x_mitre_deprecated")
    }

    result = {}

    # 1) Eski şema
    for stix_id, technique_id in patterns.items():
        for source in by_id[stix_id].get("x_mitre_data_sources") or []:
            _merge(result, technique_id, _tier_for(source))

    # 2) data-component --detects--> attack-pattern
    # 3) detection-strategy --detects--> attack-pattern (v18+)
    for rel in objects:
        if not isinstance(rel, dict) or rel.get("type") != "relationship":
            continue
        if rel.get("relationship_type") != "detects":
            continue

        technique_id = patterns.get(rel.get("target_ref"))
        source = by_id.get(rel.get("source_ref")) or {}

        if not technique_id:
            continue

        if source.get("type") == "x-mitre-data-component":
            _merge(result, technique_id, _tier_for(source.get("name")))

        elif source.get("type") == "x-mitre-detection-strategy":
            for analytic_ref in source.get("x_mitre_analytic_refs") or []:
                analytic = by_id.get(analytic_ref) or {}
                for log_source in analytic.get("x_mitre_log_source_references") or []:
                    component = by_id.get(
                        log_source.get("x_mitre_data_component_ref")
                    ) or {}
                    _merge(result, technique_id, _tier_for(component.get("name")))

    return result


def get_network_observable_set(attack_json=DEFAULT_ATTACK_JSON):
    path = str(attack_json)

    if _cache["set"] is not None and _cache["path"] == path:
        return _cache["set"], _cache["source"]

    derived = {}

    try:
        if Path(path).exists():
            derived = derive_from_attack_json(path)
    except Exception as exc:
        print("NETWORK MITRE SET DERIVATION FAILED ->", repr(exc))

    if derived:
        _cache.update(path=path, set=derived, source=f"attack_json:{Path(path).name}")
    else:
        _cache.update(path=path, set=dict(FALLBACK_SET), source="fallback")

    print(
        "NETWORK OBSERVABLE MITRE SET ->",
        len(_cache["set"]),
        "techniques",
        f"(source={_cache['source']})",
    )

    return _cache["set"], _cache["source"]


def technique_tier(technique_id, observable_set):
    technique_id = str(technique_id or "").upper()
    if technique_id in observable_set:
        return observable_set[technique_id]
    return observable_set.get(technique_id.split(".")[0])


def _candidate_id(candidate):
    if isinstance(candidate, dict):
        for key in ("id", "technique_id", "attack_id", "external_id", "mitre_id"):
            if candidate.get(key):
                return str(candidate[key]).upper()
        return None

    match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", str(candidate), re.IGNORECASE)
    return match.group(0).upper() if match else None


def filter_mitre_analysis(mitre_analysis, has_payload_evidence=False, attack_json=DEFAULT_ATTACK_JSON):
    """
    MITRE sonucunu sensörün görebildiği tekniklerle sınırlar.
    Elenenler 'network_observable_filter.removed' altında saklanır.
    """
    if not isinstance(mitre_analysis, dict):
        return mitre_analysis

    observable, source = get_network_observable_set(attack_json)

    result = mitre_analysis.get("result") or {}
    techniques = result.get("techniques") or []

    kept, removed = [], []

    for technique in techniques:
        tier = technique_tier(technique.get("id"), observable)

        if tier is None:
            removed.append(technique.get("id"))
            continue

        technique = dict(technique)
        technique["visibility"] = tier

        if tier == "content_visible" and not has_payload_evidence:
            technique["requires_payload_evidence"] = True

        kept.append(technique)

    candidates = [
        candidate
        for candidate in mitre_analysis.get("candidates") or []
        if technique_tier(_candidate_id(candidate), observable) is not None
    ]

    filtered = dict(mitre_analysis)
    filtered["result"] = {**result, "techniques": kept}
    filtered["candidates"] = candidates
    filtered["network_observable_filter"] = {
        "source": source,
        "set_size": len(observable),
        "kept": [t.get("id") for t in kept],
        "removed": removed,
    }

    if techniques and not kept and filtered.get("status") == "completed":
        filtered["status"] = "insufficient_evidence"
        filtered["reason"] = "no_network_observable_technique"
        filtered["message"] = (
            "Selected techniques are host-only and cannot be confirmed "
            "from network-flow evidence."
        )

    return filtered
