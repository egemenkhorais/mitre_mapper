import math
import re
from collections import defaultdict

# Behavior-level (not technique-level) query seeds.
# Unknown behaviors fall back to their own name.
BEHAVIOR_CONTEXT = {
    "internal_network_scan": (
        "internal network service discovery remote system discovery "
        "host discovery port scanning"
    ),
    "possible_lateral_movement": "lateral movement remote services internal remote access",
    "network_service_discovery": "network service discovery port scanning internal systems",
    "remote_system_discovery": "remote system discovery internal host enumeration",
    "smb_activity": "smb windows admin shares network share discovery remote services",
    "credential_access": "credential access credential dumping password authentication",
    "command_and_control": "command and control network communication",
    "data_exfiltration": "exfiltration data transfer external network",
}

# Ports that are not discriminative on their own (web/DNS) -> never turned into a query.
GENERIC_PORTS = {53, 80, 443, 8080, 8443}

# Ports already covered by dedicated queries below (SMB / remote services).
COVERED_PORTS = {22, 139, 445, 3389, 5985, 5986}

PORT_CONTEXT = {
    21: "ftp service",
    23: "telnet remote service",
    25: "smtp service",
    88: "kerberos authentication",
    135: "windows rpc service",
    389: "ldap directory service",
    636: "ldaps directory service",
    1433: "microsoft sql server",
    1521: "oracle database",
    3306: "mysql database",
    5432: "postgresql database",
}

# Behavior keyword -> ATT&CK TACTIC (tactic level, not technique level).
TACTIC_HINTS = {
    "discovery": "discovery",
    "enumeration": "discovery",
    "lateral": "lateral-movement",
    "movement": "lateral-movement",
    "credential": "credential-access",
    "brute": "credential-access",
    "password": "credential-access",
    "exfiltration": "exfiltration",
    "beacon": "command-and-control",
    "beaconing": "command-and-control",
    "command": "command-and-control",
    "c2": "command-and-control",
    "flood": "impact",
    "dos": "impact",
    "ddos": "impact",
    "persistence": "persistence",
}

PRE_COMPROMISE_TACTICS = {"reconnaissance", "resource-development"}

NAME_STOPWORDS = {"of", "and", "the", "to", "via", "or", "a", "in", "for", "with", "from", "on", "by"}


def normalize_behavior_name(value):
    if not value:
        return ""
    value = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    return re.sub(r"[^a-z0-9_]+", "", value)


def safe_number(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def unique_preserve_order(values):
    seen = set()
    result = []
    for value in values:
        value = str(value).strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def tokenize(text):
    return re.findall(r"[a-z0-9]+", str(text).lower().replace("_", " "))


def stem(token):
    if len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def normalize_tactic(value):
    return str(value).strip().lower().replace("_", "-").replace(" ", "-")


def extract_ports(evidence):
    ports = []
    for port in evidence.get("ports") or []:
        try:
            ports.append(int(port))
        except (TypeError, ValueError):
            pass
    try:
        ports.append(int(evidence.get("destination_port")))
    except (TypeError, ValueError):
        pass
    return list(dict.fromkeys(ports))


# --------------------------------------------------------------------------
# Query building
# --------------------------------------------------------------------------
def build_queries_for_finding(finding):
    behavior = normalize_behavior_name(finding.get("behavior", ""))
    evidence = finding.get("evidence") or {}
    queries = []

    base = BEHAVIOR_CONTEXT.get(behavior, behavior.replace("_", " "))
    if base:
        queries.append(base)

    ports = extract_ports(evidence)

    # Only discriminative ports that have no dedicated query below.
    port_terms = [
        PORT_CONTEXT[p]
        for p in ports
        if p in PORT_CONTEXT and p not in GENERIC_PORTS and p not in COVERED_PORTS
    ]
    if port_terms:
        queries.append(" ".join(unique_preserve_order(port_terms)))

    smb_connections = safe_number(evidence.get("smb_connections"))
    if smb_connections > 0 or 445 in ports or 139 in ports:
        queries.append(
            "smb windows admin shares network share discovery "
            "remote services lateral movement"
        )

    unique_targets = safe_number(evidence.get("unique_targets"))
    unique_ports = safe_number(evidence.get("unique_ports"))

    if unique_targets >= 10:
        queries.append(
            "remote system discovery internal host discovery multiple destination systems"
        )
    if unique_ports >= 5:
        queries.append("network service discovery port scanning multiple services")
    if unique_targets >= 10 and unique_ports >= 5:
        queries.append(
            "internal network service discovery remote system discovery "
            "horizontal vertical port scan"
        )

    remote_terms = []
    if 22 in ports:
        remote_terms.append("ssh remote services")
    if 3389 in ports:
        remote_terms.append("rdp remote desktop services")
    if 5985 in ports or 5986 in ports:
        remote_terms.append("windows remote management winrm")
    if 445 in ports or 139 in ports:
        remote_terms.append("smb windows admin shares")
    if remote_terms:
        queries.append("lateral movement " + " ".join(remote_terms))

    metadata = {
        "behavior": behavior,
        "confidence": safe_number(finding.get("confidence")),
        "behavior_score": safe_number(finding.get("score")),
        "evidence": evidence,
    }
    return unique_preserve_order(queries), metadata


def calculate_query_weight(metadata):
    confidence = metadata.get("confidence") or 0.5
    behavior_score = min(max(metadata.get("behavior_score", 0.0) / 100.0, 0.0), 1.0)
    return 0.70 * confidence + 0.30 * behavior_score


def normalize_scores(results):
    if not results:
        return []
    raw = [max(safe_number(r.get("match_score")), 0.0) for r in results]
    maximum = max(raw) or 1.0
    normalized = []
    for result, score in zip(results, raw):
        item = dict(result)
        item["normalized_score"] = score / maximum
        normalized.append(item)
    return normalized


# --------------------------------------------------------------------------
# Generic (technique-ID-free) evidence scoring
# --------------------------------------------------------------------------
def is_internal_context(metadata):
    tokens = set(tokenize(metadata.get("behavior", "")))
    return bool(tokens & {"internal", "lateral"})


def expected_tactics(metadata):
    behavior_tokens = tokenize(metadata.get("behavior", ""))
    evidence = metadata.get("evidence") or {}
    expected = set()

    for token in behavior_tokens:
        tactic = TACTIC_HINTS.get(token)
        if tactic:
            expected.add(tactic)

    if "scan" in behavior_tokens or "scanning" in behavior_tokens:
        expected.add("discovery")
        if not is_internal_context(metadata):
            expected.add("reconnaissance")

    if (
        safe_number(evidence.get("unique_targets")) >= 10
        or safe_number(evidence.get("unique_ports")) >= 5
    ):
        expected.add("discovery")

    if safe_number(evidence.get("smb_connections")) > 0:
        expected.add("lateral-movement")

    return expected


def build_vocabulary(queries, metadata, synonyms):
    tokens = set()
    for query in queries:
        tokens.update(tokenize(query))
    tokens.update(tokenize(metadata.get("behavior", "")))
    for key in (metadata.get("evidence") or {}):
        tokens.update(tokenize(key))

    expanded = set(tokens)
    for token in tokens:
        expanded.update(synonyms.get(token, ()))

    return {stem(token) for token in expanded}


def score_candidate_context(candidate, metadata, vocabulary, expected):
    bonus = 0.0
    reasons = []
    behavior = metadata.get("behavior", "")

    tactics = {normalize_tactic(t) for t in (candidate.get("tactics") or [])}

    # 1) Tactic alignment
    aligned = tactics & expected
    if aligned:
        bonus += 0.15
        reasons.append(
            "Tactic '%s' matches behavior '%s'" % (sorted(aligned)[0], behavior)
        )

    # 2) Scope: internal activity should not map to pre-compromise tactics
    if is_internal_context(metadata) and tactics and tactics <= PRE_COMPROMISE_TACTICS:
        bonus -= 0.25
        reasons.append("Pre-compromise tactic conflicts with internal activity")

    # 3) Name grounding: are the technique's name terms supported by queries/evidence?
    name_tokens = [
        stem(t)
        for t in tokenize(candidate.get("name", ""))
        if t not in NAME_STOPWORDS
    ]
    if name_tokens:
        missing = [t for t in name_tokens if t not in vocabulary]
        grounding = 1.0 - len(missing) / len(name_tokens)
        bonus += 0.40 * (grounding - 0.5)

        if grounding >= 0.99:
            reasons.append("Technique name fully supported by evidence terms")
        elif grounding < 0.5:
            reasons.append(
                "Technique name terms not supported by evidence: %s"
                % ", ".join(missing)
            )

    return bonus, reasons


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------
def retrieve_candidates(retriever, behavioral_findings, per_query_k=10, final_k=10):
    synonyms = getattr(retriever, "SYNONYMS", {})

    # 1) Plan: queries per finding; every unique query is executed once.
    plans = []
    query_weights = {}

    for finding in behavioral_findings:
        if not isinstance(finding, dict):
            continue
        queries, metadata = build_queries_for_finding(finding)
        metadata["weight"] = calculate_query_weight(metadata)
        plans.append((queries, metadata))

        for query in queries:
            query_weights[query] = max(query_weights.get(query, 0.0), metadata["weight"])

    # 2) Retrieve once per unique query.
    cache = {}
    for query in query_weights:
        cache[query] = normalize_scores(
            retriever.retrieve(query=query, top_k=per_query_k)
        )

    total_weight = sum(query_weights.values()) or 1.0

    # 3) Relevance: weighted lexical score, once per unique query.
    entries = {}
    for query, results in cache.items():
        weight = query_weights[query]

        for rank, candidate in enumerate(results, start=1):
            cid = candidate.get("id")
            if not cid:
                continue

            entry = entries.setdefault(
                cid,
                {
                    "candidate": dict(candidate),
                    "relevance": 0.0,
                    "bonus": 0.0,
                    "reasons": [],
                    "matches": [],
                },
            )

            normalized = safe_number(candidate.get("normalized_score"))
            coverage = safe_number(candidate.get("query_coverage"))

            entry["relevance"] += weight * (0.75 * normalized + 0.25 * coverage)
            entry["matches"].append(
                {
                    "query": query,
                    "rank": rank,
                    "match_score": candidate.get("match_score", 0.0),
                    "normalized_score": round(normalized, 6),
                    "query_coverage": candidate.get("query_coverage", 0.0),
                    "query_weight": round(weight, 6),
                }
            )

    # 4) Context bonus: ONCE per candidate per finding (not once per query).
    for queries, metadata in plans:
        vocabulary = build_vocabulary(queries, metadata, synonyms)
        expected = expected_tactics(metadata)
        scored = set()

        for query in queries:
            for candidate in cache.get(query, []):
                cid = candidate.get("id")
                if not cid or cid in scored:
                    continue
                scored.add(cid)

                bonus, reasons = score_candidate_context(
                    candidate, metadata, vocabulary, expected
                )
                entries[cid]["bonus"] += metadata["weight"] * bonus
                entries[cid]["reasons"].extend(reasons)

    # 5) Final score
    candidates = []
    for entry in entries.values():
        candidate = dict(entry["candidate"])

        relevance = entry["relevance"] / total_weight
        final_score = relevance + entry["bonus"]

        candidate["fusion_score"] = round(final_score, 6)
        candidate["relevance_score"] = round(relevance, 6)
        candidate["evidence_bonus"] = round(entry["bonus"], 6)
        candidate["query_support"] = len(entry["matches"])
        candidate["matched_queries"] = entry["matches"]
        candidate["evidence_reasons"] = unique_preserve_order(entry["reasons"])
        candidates.append(candidate)

    candidates.sort(
        key=lambda c: (c["fusion_score"], c["query_support"], c.get("match_score", 0.0)),
        reverse=True,
    )

    return {
        "queries": list(query_weights.keys()),
        "candidates": candidates[:final_k],
    }
