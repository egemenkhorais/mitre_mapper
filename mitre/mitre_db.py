# mitre_db.py

from mitre_parser import load_attack_patterns


ATTACK_DB = {}


def build_attack_db():

    global ATTACK_DB

    techniques = load_attack_patterns(
        "../cache/attack_enterprise.json"
    )

    ATTACK_DB = {
        t["id"]: t
        for t in techniques
    }



    return ATTACK_DB
