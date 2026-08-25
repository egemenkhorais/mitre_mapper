# ============================================================
# SOC PIPELINE - SIRALI CALISTIRMA SCRIPTI (HARICI / STANDALONE)
# Layer 1 (attack_classifier.joblib) -> IF WebAttackCandidate ->
# Layer 2 (payload_attack_classifier_v2.joblib)
# ============================================================
#
# NASIL CALISTIRILIR?
# ------------------------------------------------------------
#   python compute_class_medians.py   (once bir kere - onerilir)
#   python run_pipeline.py
# ============================================================

import os
import re
import sys
import json
from urllib.parse import unquote_plus

import joblib
import numpy as np
import pandas as pd


def log(*args):
    print(*args, flush=True)


LAYER1_MODEL_PATH = os.path.join("models", "attack_classifier.joblib")
LAYER2_MODEL_PATH = os.path.join("models", "payload_attack_classifier_v2.joblib")

OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

RESULTS_CSV_PATH = os.path.join(OUTPUT_DIR, "pipeline_test_results.csv")

CLASS_MEDIANS_PATH = os.path.join("models", "layer1_class_medians.joblib")


_REQUEST_LINE_PATTERN = re.compile(
    r"^(GET|POST|PUT|HEAD|DELETE|OPTIONS)\s+(\S+)\s+HTTP/\d\.\d",
    re.MULTILINE
)


def extract_payload_from_raw_http(raw_http_text):
    if not raw_http_text:
        return ""

    match = _REQUEST_LINE_PATTERN.search(raw_http_text)

    if match is None:
        return raw_http_text.strip()

    url = match.group(2)

    if "?" in url:
        _, _, query_string = url.partition("?")
    else:
        query_string = ""

    lines = raw_http_text.splitlines()
    body_lines = []
    in_body = False

    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
            continue
        if line.strip() == "":
            continue
        body_lines.append(line)

    body = "\n".join(body_lines).strip()

    combined = " ".join(
        part for part in [unquote_plus(query_string), unquote_plus(body)]
        if part
    ).strip()

    return combined


def predict_layer1(flow_dataframe, layer1_bundle, web_candidate_confidence_threshold=None):

    WEB_ATTACK_CANDIDATE_LABEL = layer1_bundle.get(
        "web_attack_candidate_label", "WebAttackCandidate"
    )

    default_threshold = layer1_bundle.get("web_candidate_confidence_threshold", 0.50)

    if web_candidate_confidence_threshold is None:
        web_candidate_confidence_threshold = default_threshold

    if flow_dataframe.empty:
        return pd.DataFrame(columns=[
            "flow_id", "predicted_attack", "confidence",
            "is_web_attack_candidate", "route_to_payload_layer",
            "next_layer", "decision_status"
        ])

    prediction_input = flow_dataframe.copy()
    prediction_input.columns = prediction_input.columns.astype(str).str.strip()

    applicable_mapping = {
        old_name: new_name
        for old_name, new_name in layer1_bundle["column_mapping"].items()
        if old_name in prediction_input.columns and new_name not in prediction_input.columns
    }
    prediction_input.rename(columns=applicable_mapping, inplace=True)

    expected_features = layer1_bundle["features"]
    missing_features = [f for f in expected_features if f not in prediction_input.columns]

    if missing_features:
        raise ValueError(
            "Tahmin girdisinde Layer 1 modelinin bekledigi "
            "feature'lar eksik:\n" + "\n".join(missing_features)
        )

    if "flow_id" in prediction_input.columns:
        input_flow_ids = prediction_input["flow_id"].astype(str).reset_index(drop=True)
    else:
        input_flow_ids = pd.Series([f"runtime-flow-{i}" for i in range(len(prediction_input))])

    prediction_X = prediction_input[expected_features].copy()

    for column in expected_features:
        prediction_X[column] = pd.to_numeric(prediction_X[column], errors="coerce").astype("float32")

    prediction_X.replace([np.inf, -np.inf], np.nan, inplace=True)

    prediction_X_clean = layer1_bundle["imputer"].transform(prediction_X).astype("float32")

    encoded_predictions = layer1_bundle["model"].predict(prediction_X_clean)
    probabilities = layer1_bundle["model"].predict_proba(prediction_X_clean)

    attack_predictions = layer1_bundle["label_encoder"].inverse_transform(encoded_predictions)
    confidence_scores = probabilities.max(axis=1)

    is_web_attack_candidate = attack_predictions == WEB_ATTACK_CANDIDATE_LABEL

    high_conf = is_web_attack_candidate & (confidence_scores >= web_candidate_confidence_threshold)
    low_conf = is_web_attack_candidate & (confidence_scores < web_candidate_confidence_threshold)

    route_to_payload_layer = high_conf | low_conf

    next_layer = np.where(route_to_payload_layer, "layer2_payload_analyzer", "layer3_mitre_mapping")

    decision_status = np.where(
        high_conf, "WEB_ATTACK_REQUIRES_PAYLOAD_ANALYSIS",
        np.where(low_conf, "LOW_CONFIDENCE_WEB_CANDIDATE_REQUIRES_REVIEW", "FLOW_ATTACK_CLASSIFICATION_COMPLETE")
    )

    return pd.DataFrame({
        "flow_id": input_flow_ids.to_numpy(),
        "predicted_attack": attack_predictions,
        "confidence": confidence_scores,
        "is_web_attack_candidate": is_web_attack_candidate,
        "route_to_payload_layer": route_to_payload_layer,
        "next_layer": next_layer,
        "decision_status": decision_status
    })


def predict_layer2(payload_text, layer2_bundle):

    if payload_text is None:
        payload_text = ""

    payload_text = str(payload_text)

    vectorizer = layer2_bundle["vectorizer"]
    model = layer2_bundle["model"]
    label_encoder = layer2_bundle["label_encoder"]

    fallback_label = layer2_bundle.get("fallback_final_label", "Web Brute Force")
    low_confidence_threshold = layer2_bundle.get("low_confidence_threshold", 0.40)
    layer1_classes = layer2_bundle.get("layer1_closed_world_classes", ["SQL Injection", "XSS"])

    if payload_text.strip() == "":
        return {
            "final_attack_type": fallback_label,
            "confidence": 0.0,
            "source": "elimination_fallback",
            "decision_basis": "Payload bos; eleme yontemiyle Web Brute Force kabul edildi."
        }

    payload_vector = vectorizer.transform([payload_text])

    predicted_encoded = model.predict(payload_vector)[0]
    probabilities = model.predict_proba(payload_vector)[0]

    predicted_category = label_encoder.inverse_transform([predicted_encoded])[0]
    confidence = float(probabilities.max())
    is_low_confidence = confidence < low_confidence_threshold

    if predicted_category in layer1_classes and not is_low_confidence:
        return {
            "final_attack_type": predicted_category,
            "confidence": confidence,
            "source": "ml_model",
            "decision_basis": f"Layer 2 modeli '{predicted_category}' tespit etti."
        }

    return {
        "final_attack_type": fallback_label,
        "confidence": confidence,
        "source": "elimination_fallback",
        "decision_basis": (
            f"Layer 2 modeli '{predicted_category}' tahmin etti (guven="
            f"{confidence:.2f}), ancak bu Layer 1'in kapali kumesinde "
            "(SQLi/XSS) degil veya guven esigin altinda. Eleme "
            "yontemiyle Web Brute Force kabul edildi."
        )
    }


def run_sequential_pipeline(flow_record, layer1_bundle, layer2_bundle):

    flow_df = pd.DataFrame([flow_record])

    layer1_result = predict_layer1(flow_df, layer1_bundle).iloc[0]

    flow_id = layer1_result["flow_id"]
    layer1_predicted_attack = layer1_result["predicted_attack"]
    layer1_confidence = float(layer1_result["confidence"])

    # ========================================================
    # ISTENEN IF YAPISI:
    # ========================================================
    if layer1_result["route_to_payload_layer"]:

        payload_text = flow_record.get("http_payload")

        if not payload_text:
            raw_request = flow_record.get("raw_http_request", "")
            payload_text = extract_payload_from_raw_http(raw_request)

        layer2_result = predict_layer2(payload_text, layer2_bundle)

        return {
            "flow_id": flow_id,
            "layer1_predicted_attack": layer1_predicted_attack,
            "layer1_confidence": layer1_confidence,
            "routed_to_layer2": True,
            "payload_used": payload_text,
            "final_attack_type": layer2_result["final_attack_type"],
            "resolved_by": "layer_2_payload_model",
            "decision_source": layer2_result["source"],
            "final_confidence": layer2_result["confidence"],
            "decision_basis": layer2_result["decision_basis"]
        }

    else:

        return {
            "flow_id": flow_id,
            "layer1_predicted_attack": layer1_predicted_attack,
            "layer1_confidence": layer1_confidence,
            "routed_to_layer2": False,
            "payload_used": None,
            "final_attack_type": layer1_predicted_attack,
            "resolved_by": "layer_1_flow_model",
            "decision_source": "ml_model",
            "final_confidence": layer1_confidence,
            "decision_basis": "Layer 1 flow modeli dogrudan kesin sinif verdi (Layer 2'ye gerek yok)."
        }


_class_medians_cache = None
_class_medians_loaded = False


def _load_class_medians():

    global _class_medians_cache, _class_medians_loaded

    if _class_medians_loaded:
        return _class_medians_cache

    _class_medians_loaded = True

    if os.path.exists(CLASS_MEDIANS_PATH):
        _class_medians_cache = joblib.load(CLASS_MEDIANS_PATH)
        log("\nSinif-bazli medyan dosyasi bulundu ve yuklendi:", CLASS_MEDIANS_PATH)
        log("Mevcut sinif medyanlari:", list(_class_medians_cache.keys()))
    else:
        _class_medians_cache = None
        log(
            "\nUYARI: Sinif-bazli medyan dosyasi bulunamadi "
            f"({CLASS_MEDIANS_PATH}). Test flow'lari GENEL "
            "(tum veri setinin) medyanini taban alacak. Daha "
            "gercekci test girdileri icin once 'python "
            "compute_class_medians.py' calistirmaniz onerilir."
        )

    return _class_medians_cache


def build_flow_record(overrides, layer1_bundle, base_class=None):

    features = layer1_bundle["features"]

    class_medians = _load_class_medians()

    base_vector = None

    if base_class is not None and class_medians is not None:

        if base_class in class_medians:
            base_vector = class_medians[base_class]
        else:
            log(
                f"\nUYARI: '{base_class}' sinifi icin medyan "
                "bulunamadi (mevcut siniflar: "
                f"{list(class_medians.keys())}). Genel medyana "
                "fallback yapiliyor."
            )

    if base_vector is not None:

        record = {}

        for feature in features:

            value = base_vector.get(feature, np.nan)

            if value is None or (isinstance(value, float) and np.isnan(value)):
                feature_index = features.index(feature)
                value = float(layer1_bundle["imputer"].statistics_[feature_index])

            record[feature] = float(value)

    else:

        imputer = layer1_bundle["imputer"]
        median_values = imputer.statistics_

        record = {
            feature: float(median_value)
            for feature, median_value in zip(features, median_values)
        }

    record.update(overrides)

    return record


# HER ELEMAN: (aciklama_etiketi, base_class, overrides_sozlugu)
TEST_FLOWS = [

    ("SQLi payload iceren web-saldirisi-benzeri flow", "WebAttackCandidate", {
        "flow_id": "test-1-sqli",
        "http_payload": "user=admin&pass=' OR '1'='1",
    }),

    ("XSS payload iceren web-saldirisi-benzeri flow", "WebAttackCandidate", {
        "flow_id": "test-2-xss",
        "http_payload": "comment=<script>alert(document.cookie)</script>",
    }),

    ("Ham HTTP istegi olarak verilmis SQLi ornegi", "WebAttackCandidate", {
        "flow_id": "test-3-raw-http",
        "raw_http_request": (
            "POST http://internal-app.local/login.jsp HTTP/1.1\r\n"
            "Host: internal-app.local\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 40\r\n"
            "\r\n"
            "user=admin&pass=%27%20OR%20%271%27%3D%271"
        ),
    }),

    ("DDoS-benzeri flow (Layer 2'ye HIC gitmemeli)", "DDoS", {
        "flow_id": "test-4-ddos",
    }),

    ("Bilinmeyen/gurultulu payload (eleme -> Web Brute Force beklenir)", "WebAttackCandidate", {
        "flow_id": "test-5-bruteforce",
        "http_payload": "username=admin&password=wrongpass123",
    }),

    ("Infiltration-benzeri flow (Layer 2'ye HIC gitmemeli)", "Infiltration", {
        "flow_id": "test-6-infiltration",
    }),

    ("PortScan-benzeri flow (Layer 2'ye HIC gitmemeli)", "PortScan", {
        "flow_id": "test-7-portscan",
    }),

]


if __name__ == "__main__":

    log("=" * 80)
    log("SOC PIPELINE BASLATILIYOR - Modeller yukleniyor...")
    log("=" * 80)

    if not os.path.exists(LAYER1_MODEL_PATH):
        raise FileNotFoundError(
            f"Layer 1 modeli bulunamadi: {LAYER1_MODEL_PATH}\n"
            "Once layer1.ipynb notebook'unu calistirip modelin "
            "egitilmis/kaydedilmis oldugundan emin olun."
        )

    if not os.path.exists(LAYER2_MODEL_PATH):
        raise FileNotFoundError(
            f"Layer 2 modeli bulunamadi: {LAYER2_MODEL_PATH}\n"
            "Once layer2.ipynb notebook'unu calistirip modelin "
            "egitilmis/kaydedilmis oldugundan emin olun."
        )

    log("Layer 1 modeli yukleniyor:", LAYER1_MODEL_PATH)
    layer1_bundle = joblib.load(LAYER1_MODEL_PATH)

    log("Layer 2 modeli yukleniyor:", LAYER2_MODEL_PATH)
    layer2_bundle = joblib.load(LAYER2_MODEL_PATH)

    log("\nLayer 1 saldiri siniflari:", list(layer1_bundle["label_encoder"].classes_))
    log("Layer 2 saldiri kategorileri:", list(layer2_bundle["label_encoder"].classes_))
    log("\nModeller basariyla yuklendi.\n")

    log("=" * 80)
    log(f"{len(TEST_FLOWS)} TEST GIRDISI ISLENIYOR")
    log("=" * 80)

    all_results = []

    for description, base_class, overrides in TEST_FLOWS:

        flow_record = build_flow_record(overrides, layer1_bundle, base_class=base_class)

        result = run_sequential_pipeline(flow_record, layer1_bundle, layer2_bundle)

        result["test_description"] = description

        all_results.append(result)

        log(f"\n--- {description} ---")
        log(f"  flow_id                 : {result['flow_id']}")
        log(f"  Layer 1 tahmini         : {result['layer1_predicted_attack']} "
            f"(guven={result['layer1_confidence']:.4f})")
        log(f"  Layer 2'ye yonlendirildi : {result['routed_to_layer2']}")

        if result["routed_to_layer2"]:
            log(f"  Kullanilan payload      : {result['payload_used']!r}")

        log(f"  NIHAI SONUC             : {result['final_attack_type']}")
        log(f"  Karar kaynagi            : {result['decision_source']} "
            f"({result['resolved_by']})")
        log(f"  Guven                    : {result['final_confidence']:.4f}")
        log(f"  Aciklama                : {result['decision_basis']}")

    results_df = pd.DataFrame(all_results)

    log("\n" + "=" * 80)
    log("OZET TABLO")
    log("=" * 80)
    log(
        results_df[[
            "flow_id", "layer1_predicted_attack", "routed_to_layer2",
            "final_attack_type", "resolved_by", "final_confidence"
        ]].to_string(index=False)
    )

    results_df.to_csv(RESULTS_CSV_PATH, index=False)
    log("\nSonuclar kaydedildi:", RESULTS_CSV_PATH)

    n_routed = int(results_df["routed_to_layer2"].sum())
    log(f"\nToplam test: {len(results_df)} | Layer 2'ye yonlendirilen: {n_routed} | "
        f"Layer 1'de kesinlesen: {len(results_df) - n_routed}")