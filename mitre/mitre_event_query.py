def normalize_text(value):
    if value is None:
        return ""
    return str(value).replace("_", " ").replace("-", " ").strip().lower()


def build_behavior_queries(behavioral_findings):
    queries = []

    for finding in behavioral_findings:
        if isinstance(finding, str):
            behavior = normalize_text(finding)
        elif isinstance(finding, dict):
            behavior = normalize_text(finding.get("behavior", ""))
        else:
            continue

        if behavior:
            queries.append(behavior)

    return list(dict.fromkeys(queries))