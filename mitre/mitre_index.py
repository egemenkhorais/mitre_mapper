from collections import defaultdict

from mitre_db import build_attack_db

ATTACK_DB = build_attack_db()

TACTIC_INDEX = defaultdict(list)

for technique in ATTACK_DB.values():

    for tactic in technique.get(
        "tactics",
        []
    ):
        TACTIC_INDEX[
            tactic.lower()
        ].append(
            technique
        )

print(TACTIC_INDEX.keys())