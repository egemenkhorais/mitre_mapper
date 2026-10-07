# mitre_parser.py

import json


def load_attack_patterns(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    techniques = []

    for obj in data["objects"]:

        if obj.get("type") != "attack-pattern":
            continue

        if obj.get(
            "revoked",
            False
        ):
            continue

        if obj.get(
            "x_mitre_deprecated",
            False
        ):
            continue

        external_refs = obj.get(
            "external_references",
            []
        )

        technique_id = None

        for ref in external_refs:

            if (
                ref.get("source_name")
                == "mitre-attack"
            ):

                technique_id = ref.get(
                    "external_id"
                )

                break

        if not technique_id:
            continue

        tactics = []

        for phase in obj.get(
            "kill_chain_phases",
            []
        ):

            phase_name = phase.get(
                "phase_name"
            )

            if phase_name:
                tactics.append(
                    phase_name
                )

        techniques.append(
            {
                "id": technique_id,
                "name": obj.get(
                    "name",
                    ""
                ),
                "description": obj.get(
                    "description",
                    ""
                ),
                "tactics": tactics,
            }
        )

    return techniques