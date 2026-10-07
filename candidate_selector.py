from mitre.mitre_index import TACTIC_INDEX

LABEL_TO_TACTIC = {
    "Reconnaissance": [
        "reconnaissance",
        "discovery"
    ],
    "Brute Force": [
        "credential-access"
    ],
    "password": [
        "credential-access"
    ],
    "Exploitation": [
        "initial-access",
        "execution",
        "privilege-escalation"
    ],
    "Infiltration": [
        "initial-access",
        "lateral-movement",
        "collection"
    ],
    "Bot": [
        "command-and-control"
    ],
    "Backdoor": [
        "persistence",
        "command-and-control"
    ],
    "Ransomware": [
        "impact"
    ],
    "Theft": [
        "collection",
        "exfiltration"
    ],
    "MITM": [
        "credential-access",
        "collection"
    ],
    "DoS": [
        "impact"
    ],
    "DDoS": [
        "impact"
    ],
    "Worms": [
        "lateral-movement",
        "execution"
    ],
    "Fuzzers": [
        "discovery"
    ],
    "Web Attack": [
        "initial-access",
        "execution"
    ]
}


def get_candidates(attack_label):

    candidates = []

    tactics = LABEL_TO_TACTIC.get(
        attack_label,
        []
    )

    for tactic in tactics:

        candidates.extend(
            TACTIC_INDEX.get(
                tactic,
                []
            )
        )

    return candidates