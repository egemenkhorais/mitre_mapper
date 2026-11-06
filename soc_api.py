"""
soc_api.py

alerts/ klasörünü izleyip web dashboard'a JSON + SSE sunan hafif sunucu.
Ek bağımlılık yok (yalnızca standart kütüphane + proje modülleri).

Yeni:
    POST /api/alerts/<id>/validate        -> Qwen Threat Validator ("gerçekten saldırı mı?")
    POST /api/alerts/<id>/mitre[?force=1] -> MITRE (yalnızca network-observable teknikler)

Kullanım:
    python soc_api.py                      # http://127.0.0.1:8765
    python soc_api.py --port 9000 --alerts-dir /yol/alerts
"""

import argparse
import json
import os
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from soc_store import AlertStore, BASE_DIR, DEFAULT_ALERTS_DIR, DEFAULT_ATTACK_JSON

from threat_validator import (
    context_from_alert,
    validate_threat,
    is_attack_verdict,
)

DASHBOARD_FILE = BASE_DIR / "dashboard.html"

# live_soc.py ile aynı eşik
SUSPICIOUS_MITRE_MIN_CONFIDENCE = 0.80

store = None  # main() içinde oluşturulur

_action_locks = {}
_action_locks_guard = threading.Lock()


def _alert_lock(alert_id):
    with _action_locks_guard:
        return _action_locks.setdefault(alert_id, threading.Lock())


# ==========================================================
# HELPERS
# ==========================================================

def trim_raw(raw):
    raw_trimmed = dict(raw)

    mitre = dict(raw_trimmed.get("mitre_analysis") or {})
    mitre.pop("raw_output", None)  # çok büyük olabilir
    raw_trimmed["mitre_analysis"] = mitre

    validation = dict(raw_trimmed.get("threat_validation") or {})
    validation.pop("raw_response", None)
    raw_trimmed["threat_validation"] = validation

    raw_trimmed.pop("validation_context", None)

    return raw_trimmed


def enrich(record):
    """Store kaydına validator/MITRE alanlarını ham JSON'dan ekler."""
    if record is None:
        return None

    record = dict(record)
    raw = store.raw(record["id"]) or {}

    validation = raw.get("threat_validation") or {}
    mitre = raw.get("mitre_analysis") or {}

    record["verdict"] = validation.get("verdict")
    record["verdict_confidence"] = validation.get("confidence")
    record["validation_status"] = validation.get("status", "not_run")
    record["validation_reason"] = validation.get("reason")

    if mitre.get("status"):
        record["mitre_status"] = mitre.get("status")
        record["mitre_reason"] = mitre.get("reason")

    return record


def find_record(alert_id):
    return next(
        (a for a in store.alerts(limit=0) if a["id"] == alert_id),
        None,
    )


def locate_metadata_file(alert_id, raw):
    candidates = []

    if raw.get("metadata_file"):
        candidates.append(Path(raw["metadata_file"]))

    if raw.get("pcap_file"):
        pcap = Path(raw["pcap_file"])
        candidates.append(pcap.with_name(pcap.stem + ".json"))

    candidates.append(Path(store.alerts_dir) / f"{alert_id}.json")

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def write_json_atomic(path, payload):
    path = Path(path)
    temp_path = path.with_name(path.name + ".tmp")

    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4, ensure_ascii=False, default=str)

    os.replace(temp_path, path)


def load_alert_for_update(alert_id):
    raw = store.raw(alert_id)

    if raw is None:
        return None, None, "alert not found"

    metadata_file = locate_metadata_file(alert_id, raw)

    if metadata_file is None:
        return None, None, "metadata file not found"

    # Diskteki en güncel hali oku (store eski olabilir).
    with metadata_file.open("r", encoding="utf-8") as handle:
        metadata = json.load(handle)

    return metadata, metadata_file, None


def mitre_skipped(status, reason, message):
    return {
        "status": status,
        "reason": reason,
        "message": message,
        "result": {"techniques": []},
        "candidates": [],
        "timing": {"retrieval_seconds": 0.0, "qwen_seconds": 0.0, "total_seconds": 0.0},
    }


# ==========================================================
# ACTIONS
# ==========================================================

def action_validate(alert_id):
    metadata, metadata_file, error = load_alert_for_update(alert_id)

    if error:
        return 404, {"error": error}

    context = context_from_alert(metadata)
    validation = validate_threat(context)
    validation["triggered_by"] = "dashboard"
    validation["validated_at"] = time.time()

    metadata["threat_validation"] = validation
    metadata["validation_context"] = context
    metadata["final_verdict"] = validation.get("verdict") or "Unvalidated"

    current_mitre = metadata.get("mitre_analysis") or {}

    # Daha önce MITRE tamamlanmadıysa durumunu yeni verdict'e göre güncelle.
    if current_mitre.get("status") not in ("completed", "insufficient_evidence"):
        if is_attack_verdict(validation, SUSPICIOUS_MITRE_MIN_CONFIDENCE):
            metadata["mitre_analysis"] = mitre_skipped(
                "deferred",
                "awaiting_user_request",
                "Attack confirmed. Use 'MITRE Eşle'.",
            )
        else:
            metadata["mitre_analysis"] = mitre_skipped(
                "skipped",
                "verdict_not_attack",
                f"MITRE not needed: verdict={validation.get('verdict')}.",
            )

    write_json_atomic(metadata_file, metadata)
    store.refresh()

    return 200, {"alert": enrich(find_record(alert_id)), "raw": trim_raw(metadata)}


def action_mitre(alert_id, force=False):
    metadata, metadata_file, error = load_alert_for_update(alert_id)

    if error:
        return 404, {"error": error}

    validation = metadata.get("threat_validation") or {}

    if not force and not is_attack_verdict(validation, SUSPICIOUS_MITRE_MIN_CONFIDENCE):
        return 409, {
            "error": "not_confirmed_attack",
            "message": (
                "Threat Validator bu alert'i saldırı olarak doğrulamadı "
                f"(verdict={validation.get('verdict')}). "
                "Yine de çalıştırmak için force=1."
            ),
        }

    # Lazy import: MITRE retriever yalnızca ilk butonda yüklenir.
    from mitre_runner import run_mitre_from_alert

    mitre = run_mitre_from_alert(metadata, validation)
    mitre["triggered_by"] = "dashboard_forced" if force else "dashboard"

    metadata["mitre_analysis"] = mitre

    write_json_atomic(metadata_file, metadata)
    store.refresh()

    return 200, {"alert": enrich(find_record(alert_id)), "raw": trim_raw(metadata)}


# ==========================================================
# HTTP
# ==========================================================

class Handler(BaseHTTPRequestHandler):
    server_version = "SocAPI/2.0"

    def log_message(self, fmt, *args):
        pass  # konsolu sessiz tut

    # ---------------------------------------------------------
    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        try:
            body = Path(path).read_bytes()
        except OSError:
            self._send_json({"error": "not found"}, 404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---------------------------------------------------------
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)  # gövde kullanılmıyor

        if not path.startswith("/api/alerts/"):
            self._send_json({"error": "not found"}, 404)
            return

        rest = path[len("/api/alerts/"):]

        if "/" not in rest:
            self._send_json({"error": "not found"}, 404)
            return

        alert_id, action = rest.rsplit("/", 1)
        alert_id = unquote(alert_id)

        store.refresh()

        lock = _alert_lock(alert_id)

        if not lock.acquire(blocking=False):
            self._send_json({"error": "busy", "message": "Bu alert için işlem zaten sürüyor."}, 429)
            return

        try:
            if action == "validate":
                status, payload = action_validate(alert_id)
            elif action == "mitre":
                force = query.get("force", ["0"])[0] in ("1", "true", "yes")
                status, payload = action_mitre(alert_id, force=force)
            else:
                status, payload = 404, {"error": "unknown action"}
        except Exception as exc:
            status, payload = 500, {"error": type(exc).__name__, "message": str(exc)}
        finally:
            lock.release()

        self._send_json(payload, status)

    # ---------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path in ("/", "/index.html", "/dashboard.html"):
            self._send_file(DASHBOARD_FILE, "text/html; charset=utf-8")
            return

        store.refresh()

        if path == "/api/health":
            self._send_json(
                {
                    "ok": True,
                    "alerts_dir": str(store.alerts_dir),
                    "alerts_dir_exists": store.alerts_dir.exists(),
                    "catalog_source": store.catalog.source,
                    "alert_count": len(store.alerts(limit=0)),
                }
            )

        elif path == "/api/alerts":
            try:
                limit = min(int(query.get("limit", ["100"])[0]), 1000)
            except ValueError:
                limit = 100
            self._send_json(
                {
                    "alerts": [enrich(a) for a in store.alerts(limit=limit)],
                    "max_seq": store.max_seq(),
                }
            )

        elif path.startswith("/api/alerts/"):
            alert_id = unquote(path[len("/api/alerts/"):])
            record = find_record(alert_id)
            raw = store.raw(alert_id)
            if record is None or raw is None:
                self._send_json({"error": "not found"}, 404)
            else:
                self._send_json({"alert": enrich(record), "raw": trim_raw(raw)})

        elif path == "/api/stats":
            stats = store.stats()
            verdicts = Counter()
            for a in store.alerts(limit=0):
                raw = store.raw(a["id"]) or {}
                v = (raw.get("threat_validation") or {}).get("verdict")
                verdicts[v or "Unvalidated"] += 1
            stats["by_verdict"] = dict(verdicts)
            self._send_json(stats)

        elif path == "/api/matrix":
            self._send_json(store.matrix())

        elif path == "/api/mappings":
            self._send_json({"mappings": store.mappings()})

        elif path.startswith("/api/technique/"):
            self._send_json(store.technique_info(unquote(path.rsplit("/", 1)[1])))

        elif path == "/api/navigator":
            techniques = {}
            for m in store.mappings():
                tid = m["tech_id"].split(".")[0]
                entry = techniques.setdefault(
                    tid, {"techniqueID": tid, "score": 0, "comment": "", "enabled": True}
                )
                entry["score"] += m["count"]
                entry["comment"] += f"{m['attack']} x{m['count']}; "
            self._send_json(
                {
                    "name": "MITRE Mapper - live alerts",
                    "versions": {"attack": "14", "navigator": "4.8.1", "layer": "4.4"},
                    "domain": "enterprise-attack",
                    "techniques": list(techniques.values()),
                }
            )

        elif path == "/api/stream":
            self._stream()

        else:
            self._send_json({"error": "not found"}, 404)

    # ---------------------------------------------------------
    def _stream(self):
        """Server-Sent Events: yeni/güncellenen alert'leri anında iletir."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        last_seq = store.max_seq()
        last_beat = time.time()

        try:
            while True:
                store.refresh()
                fresh = store.alerts_since(last_seq)

                for alert in fresh:
                    data = json.dumps(enrich(alert), ensure_ascii=False, default=str)
                    self.wfile.write(f"event: alert\ndata: {data}\n\n".encode("utf-8"))
                    last_seq = max(last_seq, alert["seq"])

                if fresh:
                    self.wfile.flush()
                    last_beat = time.time()
                elif time.time() - last_beat > 15:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    last_beat = time.time()

                time.sleep(1.0)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


def main():
    global store

    parser = argparse.ArgumentParser(description="MITRE Mapper live SOC API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--alerts-dir", default=str(DEFAULT_ALERTS_DIR))
    parser.add_argument("--attack-json", default=str(DEFAULT_ATTACK_JSON))
    args = parser.parse_args()

    # MITRE çağrısı geçici olarak CWD değiştirir -> yollar mutlak olmalı.
    store = AlertStore(
        str(Path(args.alerts_dir).resolve()),
        str(Path(args.attack_json).resolve()),
    )
    store.refresh()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True

    print(f"Alerts dir : {store.alerts_dir}")
    print(f"ATT&CK data: {store.catalog.source}")
    print(f"Dashboard  : http://{args.host}:{args.port}/")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
