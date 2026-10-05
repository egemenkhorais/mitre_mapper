BENIGN_LABELS = {
    "benign",
    "normal",
    "background",
}


def normalize_confidence(value):
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0

    return min(max(confidence, 0.0), 1.0)


def get_payload_score(payload_result):
    if not isinstance(payload_result, dict):
        return 0

    try:
        score = int(payload_result.get("score", 0))
    except (TypeError, ValueError):
        score = 0

    return min(max(score, 0), 100)


def correlate(
    xgb_result,
    payload_result=None,
    behavioral_findings=None,
):
    if payload_result is None:
        payload_result = {
            "status": "not_analyzed",
            "score": 0,
            "findings": [],
        }

    if behavioral_findings is None:
        behavioral_findings = []

    label = str(
        xgb_result.get("label", "Unknown")
    ).strip()

    confidence = normalize_confidence(
        xgb_result.get("confidence", 0.0)
    )

    is_benign_prediction = (
        label.lower() in BENIGN_LABELS
    )

    # XGBoost saldırı diyorsa confidence doğrudan taban risktir.
    # Benign diyorsa yüksek Benign confidence'ını saldırı riski
    # olarak kullanmıyoruz.
    if is_benign_prediction:
        base_score = 0
    else:
        base_score = int(round(confidence * 100))

    behavior_bonus = sum(
        max(0, int(finding.get("score", 0)))
        for finding in behavioral_findings
    )

    payload_bonus = get_payload_score(payload_result)

    risk_score = min(
        base_score + behavior_bonus + payload_bonus,
        100,
    )

    mitre = sorted(
        {
            finding["mitre"]
            for finding in behavioral_findings
            if finding.get("mitre")
        }
    )

    if risk_score >= 85:
        severity = "critical"
    elif risk_score >= 70:
        severity = "high"
    elif risk_score >= 40:
        severity = "medium"
    elif risk_score > 0:
        severity = "low"
    else:
        severity = "informational"

    definitive_attack = (
        not is_benign_prediction
        and confidence >= 0.80
        and (
            len(behavioral_findings) > 0
            or payload_bonus > 0
        )
    )

    suspicious_activity = (
        risk_score >= 40
        or len(behavioral_findings) > 0
        or payload_bonus > 0
    )

    return {
        "attack": label,
        "confidence": confidence,
        "xgb_base_score": base_score,
        "behavior_score": behavior_bonus,
        "payload_score": payload_bonus,
        "risk_score": risk_score,
        "severity": severity,
        "definitive_attack": definitive_attack,
        "suspicious_activity": suspicious_activity,
        "behavioral_findings": behavioral_findings,
        "mitre_enrichment": mitre,
        "payload_result": payload_result,
    }