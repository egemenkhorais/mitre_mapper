import os
import re
import sys
import json
import argparse
from pathlib import Path
from urllib.parse import unquote_plus

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import ExtraTreesClassifier
from sklearn.impute import SimpleImputer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_MODELS_DIR = BASE_DIR / "models"

LAYER1_MODEL_FILENAME = "attack_classifier.joblib"
LAYER2_MODEL_FILENAME = "payload_attack_classifier_v2.joblib"

WEB_ATTACK_LABEL = "WebAttackCandidate"

# Morpheus girdisinin en az yüzde kaci Layer 1 feature'larini tasimali?
MIN_FEATURE_COVERAGE = 0.90
ALLOW_IMPUTATION_AFTER_COVERAGE_CHECK = True


def log(*args):
    print(*args, file=sys.stderr, flush=True)


# ============================================================
# IN-MEMORY MOCK MODEL (JOBLIB YOKSA CALISACAK FALLBACK)
# ============================================================

def create_mock_bundles():
    """
    Diskte .joblib dosyalari yoksa test amaciyla in-memory (mock) modeller uretir.
    Layer 1 ve Layer 2 bilesenlerinin hata vermeden akisi tamamlamasini saglar.
    """
    log("Test amaciyla in-memory (mock) modeller uretiliyor...")

    # Layer 1 Mock - Orijinal scriptteki feature ve mapping'ler
    requested_features = [
        "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
        "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
        "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
        "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
        "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
        "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
        "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
        "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
        "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
        "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
        "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
        "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
        "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
        "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
        "Idle Std", "Idle Max", "Idle Min"
    ]

    column_mapping = {
        "Dst Port": "Destination Port", "Tot Fwd Pkts": "Total Fwd Packets",
        "Tot Bwd Pkts": "Total Backward Packets", "TotLen Fwd Pkts": "Total Length of Fwd Packets",
        "TotLen Bwd Pkts": "Total Length of Bwd Packets", "Fwd Pkt Len Max": "Fwd Packet Length Max",
        "Fwd Pkt Len Min": "Fwd Packet Length Min", "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
        "Fwd Pkt Len Std": "Fwd Packet Length Std", "Bwd Pkt Len Max": "Bwd Packet Length Max",
        "Bwd Pkt Len Min": "Bwd Packet Length Min", "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
        "Bwd Pkt Len Std": "Bwd Packet Length Std", "Flow Byts/s": "Flow Bytes/s",
        "Flow Pkts/s": "Flow Packets/s", "Fwd IAT Tot": "Fwd IAT Total",
        "Bwd IAT Tot": "Bwd IAT Total", "Fwd Header Len": "Fwd Header Length",
        "Bwd Header Len": "Bwd Header Length", "Fwd Pkts/s": "Fwd Packets/s",
        "Bwd Pkts/s": "Bwd Packets/s", "Pkt Len Min": "Min Packet Length",
        "Pkt Len Max": "Max Packet Length", "Pkt Len Mean": "Packet Length Mean",
        "Pkt Len Std": "Packet Length Std", "Pkt Len Var": "Packet Length Variance",
        "FIN Flag Cnt": "FIN Flag Count", "SYN Flag Cnt": "SYN Flag Count",
        "RST Flag Cnt": "RST Flag Count", "PSH Flag Cnt": "PSH Flag Count",
        "ACK Flag Cnt": "ACK Flag Count", "URG Flag Cnt": "URG Flag Count",
        "CWE Flag Count": "CWE Flag Count", "ECE Flag Cnt": "ECE Flag Count",
        "Pkt Size Avg": "Average Packet Size", "Fwd Seg Size Avg": "Avg Fwd Segment Size",
        "Bwd Seg Size Avg": "Avg Bwd Segment Size", "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
        "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk", "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
        "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk", "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
        "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate", "Subflow Fwd Pkts": "Subflow Fwd Packets",
        "Subflow Fwd Byts": "Subflow Fwd Bytes", "Subflow Bwd Pkts": "Subflow Bwd Packets",
        "Subflow Bwd Byts": "Subflow Bwd Bytes", "Init Fwd Win Byts": "Init_Win_bytes_forward",
        "Init Bwd Win Byts": "Init_Win_bytes_backward", "Fwd Act Data Pkts": "act_data_pkt_fwd",
        "Fwd Seg Size Min": "min_seg_size_forward"
    }

    X_dummy_l1 = np.random.rand(5, len(requested_features))
    y_dummy_l1 = ["WebAttackCandidate", "DDoS", "PortScan", "Infiltration", "Benign"]

    le1 = LabelEncoder()
    y_enc1 = le1.fit_transform(y_dummy_l1)

    imp1 = SimpleImputer(strategy="median")
    X_imp1 = imp1.fit_transform(X_dummy_l1)

    model1 = ExtraTreesClassifier(n_estimators=10, random_state=42)
    model1.fit(X_imp1, y_enc1)

    layer1_bundle = {
        "model": model1,
        "imputer": imp1,
        "label_encoder": le1,
        "features": requested_features,
        "column_mapping": column_mapping,
        "web_attack_candidate_label": WEB_ATTACK_LABEL
    }

    # Layer 2 Mock
    X_dummy_l2 = ["<script>alert(1)</script>", "' OR 1=1", "http://localhost"]
    y_dummy_l2 = ["XSS", "SQL Injection", "SSRF"]

    le2 = LabelEncoder()
    y_enc2 = le2.fit_transform(y_dummy_l2)

    vec2 = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 3), max_features=100)
    X_vec2 = vec2.fit_transform(X_dummy_l2)

    model2 = ExtraTreesClassifier(n_estimators=10, random_state=42)
    model2.fit(X_vec2, y_enc2)

    layer2_bundle = {
        "model": model2,
        "vectorizer": vec2,
        "label_encoder": le2,
        "fallback_final_label": "Web Brute Force",
        "layer1_closed_world_classes": ["SQL Injection", "XSS"],
        "low_confidence_threshold": 0.40
    }

    return layer1_bundle, layer2_bundle


# ============================================================
# HAM HTTP ISTEGINDEN PAYLOAD CIKARMA
# ============================================================

REQUEST_LINE_PATTERN = re.compile(
    r"^(GET|POST|PUT|HEAD|DELETE|OPTIONS)\s+(\S+)\s+HTTP/\d\.\d",
    re.MULTILINE
)


def extract_payload_from_raw_http(raw_http_request):
    """
    Ham HTTP isteğinden URL query string ve request body'yi
    çıkarır ve URL decode uygular.
    """
    if raw_http_request is None:
        return ""

    raw_http_request = str(raw_http_request).strip()
    if not raw_http_request:
        return ""

    request_match = REQUEST_LINE_PATTERN.search(raw_http_request)

    if request_match is None:
        return raw_http_request

    url = request_match.group(2)
    query_string = url.split("?", 1)[1] if "?" in url else ""

    normalized = raw_http_request.replace("\r\n", "\n")
    header_body_parts = normalized.split("\n\n", 1)
    body = header_body_parts[1].strip() if len(header_body_parts) == 2 else ""

    decoded_query = unquote_plus(query_string)
    decoded_body = unquote_plus(body)

    return " ".join(value for value in [decoded_query, decoded_body] if value).strip()


# ============================================================
# MODEL YUKLEME
# ============================================================

def load_models(models_dir):
    models_dir = Path(models_dir).resolve()
    layer1_path = models_dir / LAYER1_MODEL_FILENAME
    layer2_path = models_dir / LAYER2_MODEL_FILENAME

    if not layer1_path.exists() or not layer2_path.exists():
        log(f"UYARI: {LAYER1_MODEL_FILENAME} veya {LAYER2_MODEL_FILENAME} bulunamadi.")
        return create_mock_bundles()

    log(f"Layer 1 modeli yukleniyor: {layer1_path}")
    layer1_bundle = joblib.load(layer1_path)

    log(f"Layer 2 modeli yukleniyor: {layer2_path}")
    layer2_bundle = joblib.load(layer2_path)

    required_layer1_keys = {"model", "imputer", "label_encoder", "features", "column_mapping"}
    required_layer2_keys = {"model", "vectorizer", "label_encoder"}

    missing_layer1_keys = required_layer1_keys - set(layer1_bundle)
    missing_layer2_keys = required_layer2_keys - set(layer2_bundle)

    if missing_layer1_keys:
        raise ValueError(f"Layer 1 bundle eksik alanlar tasiyor: {sorted(missing_layer1_keys)}")

    if missing_layer2_keys:
        raise ValueError(f"Layer 2 bundle eksik alanlar tasiyor: {sorted(missing_layer2_keys)}")

    return layer1_bundle, layer2_bundle


# ============================================================
# COLUMN NORMALIZATION
# ============================================================

def normalize_flow_columns(flow_record, layer1_bundle):
    """
    CSE-CIC-IDS2018 kısa kolon adlarını CICIDS2017 kolonlarına dönüştürür
    ve eksik olan bilindik kolonları onarır.
    """
    normalized = dict(flow_record)
    column_mapping = layer1_bundle.get("column_mapping", {})

    # 2018'in kısa isimlerini 2017'nin uzun isimlerine çevir
    for old_name, new_name in column_mapping.items():
        if old_name in normalized and new_name not in normalized:
            normalized[new_name] = normalized.pop(old_name)

    # ------------------------------------------------------------
    # EKSİK FEATURE ÇÖZÜMÜ (KAYIP 1 KOLON)
    # ------------------------------------------------------------
    # CICIDS2017'deki 'Fwd Header Length.1' kolonu aslında 'Fwd Header Length'
    # kolonunun birebir kopyası olan bir veri seti hatasıdır.
    # 2018 verisinde bu kopya kolon yoktur. Eksikse ana kolondan kopyalıyoruz.
    if "Fwd Header Length.1" not in normalized and "Fwd Header Length" in normalized:
        normalized["Fwd Header Length.1"] = normalized["Fwd Header Length"]

    return normalized


# ============================================================
# FEATURE COVERAGE KONTROLU
# ============================================================

def validate_feature_coverage(flow_record, layer1_bundle):
    expected_features = layer1_bundle["features"]
    supplied_features = [
        feature for feature in expected_features
        if feature in flow_record and flow_record[feature] is not None and str(flow_record[feature]).strip() != ""
    ]

    missing_features = [feature for feature in expected_features if feature not in supplied_features]
    coverage = len(supplied_features) / len(expected_features)

    if coverage < MIN_FEATURE_COVERAGE:
        raise ValueError(
            "\nLayer 1 girdisinde yeterli sayida gercek flow feature'i yok.\n"
            f"Beklenen feature: {len(expected_features)}\n"
            f"Gelen feature: {len(supplied_features)}\n"
            f"Coverage: %{coverage * 100:.2f}\n"
            f"Minimum coverage: %{MIN_FEATURE_COVERAGE * 100:.2f}\n\n"
        )

    if missing_features and not ALLOW_IMPUTATION_AFTER_COVERAGE_CHECK:
        raise ValueError("Eksik Layer 1 feature'lari var:\n" + "\n".join(missing_features))

    return {
        "expected_count": len(expected_features),
        "supplied_count": len(supplied_features),
        "missing_count": len(missing_features),
        "coverage": coverage,
        "missing_features": missing_features,
    }


# ============================================================
# LAYER 1 VE LAYER 2 TAHMIN
# ============================================================

def predict_layer1(flow_record, layer1_bundle):
    normalized_flow = normalize_flow_columns(flow_record, layer1_bundle)
    coverage_info = validate_feature_coverage(normalized_flow, layer1_bundle)

    expected_features = layer1_bundle["features"]
    feature_row = {feature: normalized_flow.get(feature, np.nan) for feature in expected_features}

    feature_df = pd.DataFrame([feature_row], columns=expected_features)
    for feature in expected_features:
        feature_df[feature] = pd.to_numeric(feature_df[feature], errors="coerce").astype("float32")

    feature_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    feature_matrix = layer1_bundle["imputer"].transform(feature_df).astype("float32")

    encoded_prediction = layer1_bundle["model"].predict(feature_matrix)[0]
    probability_vector = layer1_bundle["model"].predict_proba(feature_matrix)[0]
    predicted_attack = layer1_bundle["label_encoder"].inverse_transform([encoded_prediction])[0]
    confidence = float(probability_vector.max())

    class_probabilities = {
        str(class_name): round(float(probability), 6)
        for class_name, probability in zip(layer1_bundle["label_encoder"].classes_, probability_vector)
    }

    is_web_attack = (predicted_attack == layer1_bundle.get("web_attack_candidate_label", WEB_ATTACK_LABEL))

    return {
        "predicted_attack": str(predicted_attack),
        "confidence": confidence,
        "is_web_attack_candidate": bool(is_web_attack),
        "route_to_layer2": bool(is_web_attack),
        "class_probabilities": class_probabilities,
        "feature_coverage": coverage_info,
    }


def predict_layer2(payload_text, layer2_bundle):
    payload_text = "" if payload_text is None else str(payload_text)

    if not payload_text.strip():
        return {
            "raw_predicted_category": None,
            "raw_confidence": 0.0,
            "final_attack_type": "Web Brute Force",
            "final_confidence": 0.0,
            "decision_source": "empty_payload_fallback",
            "is_low_confidence": True,
            "class_probabilities": {},
            "decision_basis": "Layer 1 WebAttackCandidate dedi ancak payload bos. Web Brute Force kabul edildi.",
        }

    payload_matrix = layer2_bundle["vectorizer"].transform([payload_text])
    encoded_prediction = layer2_bundle["model"].predict(payload_matrix)[0]
    probability_vector = layer2_bundle["model"].predict_proba(payload_matrix)[0]

    raw_category = layer2_bundle["label_encoder"].inverse_transform([encoded_prediction])[0]
    raw_confidence = float(probability_vector.max())

    class_probabilities = {
        str(class_name): round(float(probability), 6)
        for class_name, probability in zip(layer2_bundle["label_encoder"].classes_, probability_vector)
    }

    low_confidence_threshold = layer2_bundle.get("low_confidence_threshold", 0.40)
    allowed_final_classes = layer2_bundle.get("layer1_closed_world_classes", ["SQL Injection", "XSS"])
    fallback_label = layer2_bundle.get("fallback_final_label", "Web Brute Force")

    if raw_category in allowed_final_classes and raw_confidence >= low_confidence_threshold:
        return {
            "raw_predicted_category": str(raw_category),
            "raw_confidence": raw_confidence,
            "final_attack_type": str(raw_category),
            "final_confidence": raw_confidence,
            "decision_source": "layer2_ml_model",
            "is_low_confidence": False,
            "class_probabilities": class_probabilities,
            "decision_basis": f"Layer 2 modeli {raw_category} tespit etti."
        }

    return {
        "raw_predicted_category": str(raw_category),
        "raw_confidence": raw_confidence,
        "final_attack_type": fallback_label,
        "final_confidence": raw_confidence,
        "decision_source": "closed_world_fallback",
        "is_low_confidence": True,
        "class_probabilities": class_probabilities,
        "decision_basis": "Ham tahmin kapali SQL Injection/XSS kumesinde degil. Web Brute Force uygulandi.",
    }


# ============================================================
# SIRALI PIPELINE
# ============================================================

def analyze_flow(flow_record, layer1_bundle, layer2_bundle):
    flow_id = str(flow_record.get("flow_id", "flow-unknown"))
    layer1_result = predict_layer1(flow_record, layer1_bundle)

    if not layer1_result["route_to_layer2"]:
        return {
            "flow_id": flow_id,
            "pipeline_status": "completed_at_layer1",
            "layer1_predicted_attack": layer1_result["predicted_attack"],
            "layer1_confidence": round(layer1_result["confidence"], 6),
            "layer1_class_probabilities": layer1_result["class_probabilities"],
            "feature_coverage": round(layer1_result["feature_coverage"]["coverage"], 6),
            "routed_to_layer2": False,
            "layer2_raw_prediction": None,
            "layer2_raw_confidence": None,
            "final_attack_type": layer1_result["predicted_attack"],
            "final_confidence": round(layer1_result["confidence"], 6),
            "resolved_by": "layer1_flow_model",
        }

    payload_text = flow_record.get("http_payload") or extract_payload_from_raw_http(
        flow_record.get("raw_http_request", ""))
    layer2_result = predict_layer2(payload_text, layer2_bundle)

    return {
        "flow_id": flow_id,
        "pipeline_status": "completed_at_layer2",
        "layer1_predicted_attack": layer1_result["predicted_attack"],
        "layer1_confidence": round(layer1_result["confidence"], 6),
        "layer1_class_probabilities": layer1_result["class_probabilities"],
        "feature_coverage": round(layer1_result["feature_coverage"]["coverage"], 6),
        "routed_to_layer2": True,
        "payload_used": payload_text,
        "layer2_raw_prediction": layer2_result["raw_predicted_category"],
        "layer2_raw_confidence": round(layer2_result["raw_confidence"], 6),
        "layer2_class_probabilities": layer2_result["class_probabilities"],
        "final_attack_type": layer2_result["final_attack_type"],
        "final_confidence": round(layer2_result["final_confidence"], 6),
        "resolved_by": layer2_result["decision_source"],
        "decision_basis": layer2_result["decision_basis"],
    }


def analyze_batch(flow_records, layer1_bundle, layer2_bundle):
    results = []
    for index, flow_record in enumerate(flow_records):
        if not isinstance(flow_record, dict):
            results.append({
                "flow_id": f"invalid-flow-{index}",
                "pipeline_status": "validation_error",
                "error": "Flow kaydi JSON object olmali.",
            })
            continue

        try:
            results.append(analyze_flow(flow_record, layer1_bundle, layer2_bundle))
        except Exception as exc:
            results.append({
                "flow_id": str(flow_record.get("flow_id", f"flow-{index}")),
                "pipeline_status": "error",
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
    return results


# ============================================================
# CLI
# ============================================================
def normalize_test_label(label):
    """Eğitimdeki etiket standardizasyonunun aynısı (Ground Truth için)"""
    import re
    label = str(label).strip()
    label = re.sub(r"\s+", " ", label)
    label = label.replace("ï¿½", "-").replace("–", "-").replace("—", "-")
    lower_label = label.casefold()

    if lower_label == "benign": return "BENIGN"
    if lower_label in {"infilteration", "infiltration"}: return "Infiltration"
    if lower_label in {"bot", "botnet"}: return "Botnet"
    if lower_label in {"portscan", "port scan"}: return "PortScan"

    if "web attack" in lower_label: return "WebAttackCandidate"
    explicit_web_labels = {"brute force -web", "brute force - web", "brute force -xss", "brute force - xss",
                           "sql injection", "sql-injection", "sqli", "xss", "cross site scripting",
                           "cross-site scripting"}
    if lower_label in explicit_web_labels: return "WebAttackCandidate"
    compact_label = re.sub(r"[\s_\-]+", "", lower_label)
    compact_web_labels = {"webattackbruteforce", "webattackxss", "webattacksqlinjection", "bruteforceweb",
                          "bruteforcexss", "sqlinjection", "sqli", "xss", "crosssitescripting"}
    if compact_label in compact_web_labels: return "WebAttackCandidate"

    if "ftp" in lower_label and ("patator" in lower_label or "brute" in lower_label): return "FTP-BruteForce"
    if "ssh" in lower_label and ("patator" in lower_label or "brute" in lower_label): return "SSH-BruteForce"

    if lower_label == "ddos": return "DDoS"
    if "ddos" in lower_label:
        if "hoic" in lower_label: return "DDoS-HOIC"
        if "loic" in lower_label and "udp" in lower_label: return "DDoS-LOIC-UDP"
        if "loic" in lower_label: return "DDoS-LOIC-HTTP"
        return "DDoS"

    if "slowhttptest" in lower_label: return "DoS Slowhttptest"
    if "slowloris" in lower_label: return "DoS slowloris"
    if "goldeneye" in lower_label: return "DoS GoldenEye"
    if "hulk" in lower_label: return "DoS Hulk"

    return label


def main():
    CSV_PATH = "data/2018/cic.csv"  # Buraya test etmek istediğin herhangi bir dosyanın yolunu yazabilirsin

    print("Loading models...")
    layer1_bundle, layer2_bundle = load_models(DEFAULT_MODELS_DIR)

    print(f"Loading dataset... ({CSV_PATH})")
    try:
        df = pd.read_csv(CSV_PATH, low_memory=False)
    except FileNotFoundError:
        print(f"\nHata: '{CSV_PATH}' bulunamadi. Dosya yolunu kontrol edin.")
        return

    df.columns = df.columns.astype(str).str.strip()
    label_col = next(
        (candidate for candidate in ["Label", "label", "Attack", "Attack Type"] if candidate in df.columns), None)

    if label_col is None:
        raise ValueError("Dataset içinde Label kolonu bulunamadı.")

    # Etiketleri test için standardize et
    df["_ground_truth"] = df[label_col].apply(normalize_test_label)

    # Benign'i çıkar
    attack_df = df[df["_ground_truth"] != "BENIGN"]

    if attack_df.empty:
        print("\nBelirtilen dosyada saldırı kaydı bulunamadı.")
        return

    print("\n--- DOSYADAKİ SALDIRI DAĞILIMI ---")
    print(attack_df["_ground_truth"].value_counts())

    # Pandas hatasını önleyen güvenli örnekleme (Her sınıftan maks 20 adet)
    sampled_frames = []
    for current_label, group in attack_df.groupby("_ground_truth"):
        sampled_group = group.sample(n=min(len(group), 20), random_state=42)
        sampled_frames.append(sampled_group)

    sample_df = pd.concat(sampled_frames, ignore_index=True)

    flow_records = []
    for idx, row in sample_df.iterrows():
        record = row.dropna().to_dict()
        record["flow_id"] = f"test-flow-{idx}"
        # Pipeline'a göndermeden önce ground truth'u kenara ayırıyoruz
        ground_truth_val = record.pop("_ground_truth")
        record["_target_label"] = ground_truth_val
        flow_records.append(record)

    print(f"\nToplam {len(flow_records)} flow analiz ediliyor... Lütfen bekleyin.\n")
    results = analyze_batch(flow_records, layer1_bundle, layer2_bundle)

    # ------------------------------------------------------------
    # SONUÇLARI KATEGORİK OLARAK ANALİZ ET
    # ------------------------------------------------------------
    category_stats = {}

    for i, result in enumerate(results):
        if result["pipeline_status"] == "error":
            continue

        ground_truth = flow_records[i]["_target_label"]

        # Layer 1 doğruluğunu ölçüyoruz
        if ground_truth == "WebAttackCandidate":
            predicted = result["layer1_predicted_attack"]
        else:
            predicted = result["final_attack_type"]

        if ground_truth not in category_stats:
            category_stats[ground_truth] = {"total": 0, "correct": 0}

        category_stats[ground_truth]["total"] += 1
        if ground_truth == predicted:
            category_stats[ground_truth]["correct"] += 1

    print("--- SALDIRI TÜRÜNE GÖRE BAŞARI ORANLARI ---")
    total_correct = 0
    total_samples = 0

    for attack_type, stats in category_stats.items():
        total = stats["total"]
        correct = stats["correct"]
        acc = (correct / total) * 100 if total > 0 else 0
        total_correct += correct
        total_samples += total

        print(f"{attack_type:<20} : %{acc:>5.1f}  ({correct}/{total})")

    overall_acc = (total_correct / total_samples) * 100 if total_samples > 0 else 0
    print("-" * 40)
    print(f"GENEL BAŞARI ORANI   : %{overall_acc:>5.1f}  ({total_correct}/{total_samples})")


if __name__ == "__main__":
    main()