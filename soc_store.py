"""
soc_store.py

live_soc.py'nin alerts/ klasörüne yazdığı <karar>_<etiket>_..._.json
dosyalarını okuyup UI'ların kullanacağı normalize kayıtlara çevirir.
Hem soc_api.py (web dashboard) hem soc_gui.py (Tkinter) bunu kullanır.

Veri kaynağı = gerçek metadata dosyaları. Mock/seed veri yoktur.
"""

import json
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_ALERTS_DIR = BASE_DIR / "alerts"
DEFAULT_ATTACK_JSON = BASE_DIR / "cache" / "attack_enterprise.json"

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_TITLES = {
    "command-and-control": "Command and Control",
}


def tactic_title(phase):
    return TACTIC_TITLES.get(phase) or phase.replace("-", " ").title()


# attack_enterprise.json yoksa kullanılacak küçük yedek tablo.
FALLBACK_TECHNIQUES = {
    "T1595": ("Active Scanning", ["reconnaissance"]),
    "T1046": ("Network Service Discovery", ["discovery"]),
    "T1190": ("Exploit Public-Facing Application", ["initial-access"]),
    "T1133": ("External Remote Services", ["initial-access", "persistence"]),
    "T1059": ("Command and Scripting Interpreter", ["execution"]),
    "T1059.007": ("JavaScript", ["execution"]),
    "T1110": ("Brute Force", ["credential-access"]),
    "T1110.001": ("Password Guessing", ["credential-access"]),
    "T1071": ("Application Layer Protocol", ["command-and-control"]),
    "T1071.001": ("Web Protocols", ["command-and-control"]),
    "T1498": ("Network Denial of Service", ["impact"]),
    "T1498.001": ("Direct Network Flood", ["impact"]),
    "T1499": ("Endpoint Denial of Service", ["impact"]),
    "T1499.002": ("Service Exhaustion Flood", ["impact"]),
}


class AttackCatalog:
    """Teknik ID -> (ad, taktikler, açıklama). STIX bundle varsa onu kullanır."""

    def __init__(self, attack_json=DEFAULT_ATTACK_JSON):
        self.techniques = {}
        self.source = "fallback"
        path = Path(attack_json)

        if path.exists():
            try:
                self._load_stix(path)
                self.source = str(path)
            except Exception as exc:
                print("ATT&CK catalog load failed ->", repr(exc))
                self.techniques = {}

        for tid, (name, tactics) in FALLBACK_TECHNIQUES.items():
            self.techniques.setdefault(
                tid, {"name": name, "tactics": tactics, "description": ""}
            )

    def _load_stix(self, path):
        with path.open("r", encoding="utf-8") as f:
            bundle = json.load(f)

        objects = bundle.get("objects", bundle) if isinstance(bundle, dict) else bundle

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            external_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    external_id = ref["external_id"]
                    break

            if not external_id:
                continue

            tactics = [
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]

            self.techniques[external_id] = {
                "name": obj.get("name", ""),
                "tactics": tactics,
                "description": obj.get("description", ""),
            }

    def lookup(self, technique_id):
        info = self.techniques.get(technique_id)
        if info is None and "." in technique_id:
            info = self.techniques.get(technique_id.split(".")[0])
        return info or {"name": "", "tactics": [], "description": ""}


def _as_list(value):
    return value if isinstance(value, list) else []


def _as_dict(value):
    return value if isinstance(value, dict) else {}


NON_ALERT_JSON_STEMS = {
    "actions_ledger",
    "waf_rules",
    "blocked_ips",
    "rate_limits",
    "incidents",
}


class AlertStore:
    def __init__(self, alerts_dir=DEFAULT_ALERTS_DIR, attack_json=DEFAULT_ATTACK_JSON):
        self.alerts_dir = Path(alerts_dir)
        self.catalog = AttackCatalog(attack_json)
        self._lock = threading.RLock()
        self._records = {}    # id -> normalized
        self._raw = {}        # id -> raw metadata
        self._sig = {}        # id -> (mtime_ns, size)
        self._seq = 0
        self._last_refresh = 0.0

    # ------------------------------------------------------------
    def normalize(self, alert_id, raw, mtime):
        correlation = _as_dict(raw.get("correlation_summary"))
        mitre = _as_dict(raw.get("mitre_analysis"))
        mitre_result = _as_dict(mitre.get("result"))
        layer2 = _as_dict(raw.get("layer2"))

        techniques = []
        for t in _as_list(mitre_result.get("techniques")):
            if not isinstance(t, dict) or not t.get("id"):
                continue
            info = self.catalog.lookup(t["id"])
            techniques.append(
                {
                    "id": t["id"],
                    "name": t.get("name") or info["name"],
                    "confidence": float(t.get("confidence") or 0.0),
                    "reason": t.get("reason", ""),
                    "tactics": info["tactics"],
                }
            )

        techniques.sort(key=lambda x: x["confidence"], reverse=True)

        primary = None
        if techniques:
            top = techniques[0]
            primary = {
                "id": top["id"],
                "name": top["name"],
                "tactic": tactic_title(top["tactics"][0]) if top["tactics"] else "Unmapped",
                "confidence": top["confidence"],
            }

        severity = str(correlation.get("severity", "informational")).lower()
        timestamp = raw.get("timestamp") or mtime

        return {
            "id": alert_id,
            "ts": float(timestamp),
            "time": datetime.fromtimestamp(float(timestamp)).strftime("%H:%M:%S"),
            "date": datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d"),
            "decision": raw.get("decision"),
            "layer1_decision": raw.get("layer1_decision"),
            "label": raw.get("label"),
            "confidence": float(raw.get("confidence") or 0.0),
            "src_ip": raw.get("src_ip"),
            "dst_ip": raw.get("dst_ip"),
            "src_port": raw.get("src_port"),
            "dst_port": raw.get("dst_port"),
            "protocol": raw.get("protocol"),
            "packet_count": raw.get("packet_count"),
            "pcap_file": raw.get("pcap_file"),
            "pcap_exported": raw.get("pcap_exported"),
            "severity": severity,
            "risk_score": float(correlation.get("risk_score", 0) or 0),
            "suspicious_activity": bool(correlation.get("suspicious_activity", False)),
            "retained_reason": raw.get("retained_reason"),
            "behaviors": [
                b.get("behavior")
                for b in _as_list(raw.get("behavioral_findings"))
                if isinstance(b, dict)
            ],
            "source_activity": _as_dict(raw.get("source_activity")),
            "layer2": {
                "label": layer2.get("label"),
                "confidence": layer2.get("confidence"),
                "status": layer2.get("status"),
            } if layer2 else None,
            "http_evidence": _as_dict(raw.get("http_evidence")) or None,
            "mitre_status": mitre.get("status", "not_run"),
            "mitre_reason": mitre.get("reason"),
            "mitre_message": mitre.get("message"),
            "mitre_reused": mitre.get("reused"),
            "mitre_candidate_count": len(_as_list(mitre.get("candidates"))),
            "techniques": techniques,
            "primary": primary,
        }

    # ------------------------------------------------------------
    def refresh(self, force=False):
        """alerts/ klasörünü tarar; yeni/değişen kayıtların id listesini döner."""
        changed = []

        if not self.alerts_dir.exists():
            return changed

        now = time.monotonic()
        if not force and (now - self._last_refresh) < 0.35:
            return changed

        seen = set()

        with self._lock:
            self._last_refresh = time.monotonic()
            for path in self.alerts_dir.glob("*.json"):
                alert_id = path.stem
                if alert_id in NON_ALERT_JSON_STEMS:
                    continue
                seen.add(alert_id)

                try:
                    stat = path.stat()
                except OSError:
                    continue

                sig = (stat.st_mtime_ns, stat.st_size)
                if self._sig.get(alert_id) == sig:
                    continue

                try:
                    with path.open("r", encoding="utf-8") as f:
                        raw = json.load(f)
                except (json.JSONDecodeError, OSError):
                    # Yazım sürüyor olabilir; sonraki taramada tekrar denenir.
                    continue

                if not isinstance(raw, dict) or "decision" not in raw:
                    continue

                try:
                    record = self.normalize(alert_id, raw, stat.st_mtime)
                except Exception:
                    continue

                # Yeni veya güncellenen her kayıt yeni bir seq alır;
                # SSE istemcileri seq'e göre yalnızca yeniyi alır.
                self._seq += 1
                record["seq"] = self._seq

                self._records[alert_id] = record
                self._raw[alert_id] = raw
                self._sig[alert_id] = sig
                changed.append(alert_id)

            for gone in set(self._records) - seen:
                self._records.pop(gone, None)
                self._raw.pop(gone, None)
                self._sig.pop(gone, None)

        return changed

    # ------------------------------------------------------------
    def alerts(self, limit=200, since_seq=0):
        with self._lock:
            items = [r for r in self._records.values() if r["seq"] > since_seq]
            items.sort(key=lambda r: r["ts"], reverse=True)
            return items[:limit] if limit else items

    def alerts_since(self, seq):
        with self._lock:
            items = [r for r in self._records.values() if r["seq"] > seq]
            items.sort(key=lambda r: r["seq"])
            return items

    def max_seq(self):
        with self._lock:
            return self._seq

    def raw(self, alert_id):
        with self._lock:
            return self._raw.get(alert_id)

    # ------------------------------------------------------------
    def stats(self):
        with self._lock:
            records = list(self._records.values())

        total = len(records)
        now = time.time()

        critical_high = [r for r in records if r["severity"] in ("critical", "high")]
        distinct_techniques = {t["id"] for r in records for t in r["techniques"]}
        distinct_tactics = {
            tac for r in records for t in r["techniques"] for tac in t["tactics"]
        }

        tactic_counter = Counter()
        for r in records:
            tactics = {tac for t in r["techniques"] for tac in t["tactics"]}
            for tac in tactics:
                tactic_counter[tactic_title(tac)] += 1

        mapped_alerts = sum(1 for r in records if r["techniques"])
        confidences = [r["confidence"] for r in records]

        top_tactics = [
            {
                "tactic": name,
                "count": count,
                "percent": round(100.0 * count / mapped_alerts, 1) if mapped_alerts else 0.0,
            }
            for name, count in tactic_counter.most_common(5)
        ]

        crit_labels = Counter(r["label"] for r in critical_high)

        return {
            "total_alerts": total,
            "last_15min": sum(1 for r in records if now - r["ts"] <= 900),
            "mapped_techniques": len(distinct_techniques),
            "mapped_tactics": len(distinct_tactics),
            "critical_high": len(critical_high),
            "critical_high_labels": [l for l, _ in crit_labels.most_common(3)],
            "avg_confidence": round(sum(confidences) / total, 4) if total else None,
            "mapped_alerts": mapped_alerts,
            "tactic_distribution": top_tactics,
            "by_decision": dict(Counter(r["decision"] for r in records)),
            "by_mitre_status": dict(Counter(r["mitre_status"] for r in records)),
            "catalog_source": self.catalog.source,
            "alerts_dir": str(self.alerts_dir),
        }

    def matrix(self):
        with self._lock:
            records = list(self._records.values())

        # tactic -> technique_id -> bilgi
        grid = defaultdict(dict)

        for r in records:
            for t in r["techniques"]:
                phases = t["tactics"] or ["unmapped"]
                for phase in phases:
                    cell = grid[phase].setdefault(
                        t["id"],
                        {
                            "id": t["id"],
                            "name": t["name"],
                            "count": 0,
                            "attacks": set(),
                            "max_severity": "informational",
                            "max_confidence": 0.0,
                        },
                    )
                    cell["count"] += 1
                    cell["attacks"].add(r["label"])
                    cell["max_confidence"] = max(cell["max_confidence"], t["confidence"])
                    if SEVERITY_RANK.get(r["severity"], 0) > SEVERITY_RANK[cell["max_severity"]]:
                        cell["max_severity"] = r["severity"]

        def level(sev):
            if sev == "critical":
                return "crit"
            if sev == "high":
                return "high"
            return "med"

        columns = []
        for phase in TACTIC_ORDER + [p for p in grid if p not in TACTIC_ORDER]:
            techs = []
            for cell in grid.get(phase, {}).values():
                techs.append(
                    {
                        "id": cell["id"],
                        "name": cell["name"],
                        "count": cell["count"],
                        "attacks": sorted(a for a in cell["attacks"] if a),
                        "level": level(cell["max_severity"]),
                        "max_confidence": cell["max_confidence"],
                    }
                )
            techs.sort(key=lambda x: x["count"], reverse=True)
            columns.append(
                {
                    "id": phase,
                    "name": tactic_title(phase) if phase != "unmapped" else "Unmapped",
                    "techniques": techs,
                }
            )

        return {"tactics": columns}

    def mappings(self):
        """Gözlenen (model etiketi -> MITRE tekniği) eşlemeleri."""
        with self._lock:
            records = list(self._records.values())

        pairs = {}
        for r in records:
            for t in r["techniques"]:
                key = (r["label"], t["id"])
                p = pairs.setdefault(
                    key,
                    {
                        "attack": r["label"],
                        "tactic": tactic_title(t["tactics"][0]) if t["tactics"] else "Unmapped",
                        "tech_id": t["id"],
                        "tech_name": t["name"],
                        "count": 0,
                        "conf_sum": 0.0,
                        "max_severity": "informational",
                    },
                )
                p["count"] += 1
                p["conf_sum"] += t["confidence"]
                if SEVERITY_RANK.get(r["severity"], 0) > SEVERITY_RANK[p["max_severity"]]:
                    p["max_severity"] = r["severity"]

        out = []
        for p in pairs.values():
            p["avg_confidence"] = round(p.pop("conf_sum") / p["count"], 4)
            out.append(p)

        out.sort(key=lambda x: x["count"], reverse=True)
        return out

    def technique_info(self, technique_id):
        info = self.catalog.lookup(technique_id)
        with self._lock:
            attacks = sorted(
                {
                    r["label"]
                    for r in self._records.values()
                    for t in r["techniques"]
                    if t["id"] == technique_id and r["label"]
                }
            )
        return {
            "id": technique_id,
            "name": info["name"],
            "tactics": [tactic_title(t) for t in info["tactics"]],
            "description": info["description"],
            "attacks": attacks,
        }