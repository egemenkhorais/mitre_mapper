# ============================================================
# SINIF-BAZLI MEDYAN HESAPLAYICI (Layer 1 icin gercekci test
# girdileri uretmek amaciyla)
# ============================================================
#
# BU SCRIPT NE ISE YARAR?
# ------------------------------------------------------------
# run_pipeline.py'deki test flow'lari, Layer 1 modelinin
# bekledigi TUM feature'lari (70 adet) doldurmak zorunda. Biz
# testlerde SADECE 8-9 feature'i elle giriyoruz (Flow Bytes/s,
# SYN Flag Count vb.); geri kalanlari GENEL (tum veri setinin)
# medyani ile doldurmustuk.
#
# SORUN: Genel medyan tek basina yeterli AYIRT EDICI bir sinyal
# tasimiyor. DDoS/WebAttackCandidate gibi siniflar, COK SAYIDA
# feature'in BIRLIKTE uc/anormal degerler almasiyla ayirt edilir
# (ornegin DDoS'ta hem cok yuksek paket hizi HEM cok kisa flow
# suresi HEM yuksek SYN flag sayisi AYNI ANDA gorulur). Sadece
# 1-2 feature override edip gerisini "genel ortalama" birakmak,
# modelin gozunde hala "sira disi olmayan, tipik" bir flow gibi
# gorunuyor - ve Infiltration (CSE-CIC-IDS2018'den 62 bin+ kayitla
# gelen, cok cesitli davranislar barindiran buyuk bir sinif)
# veri setinin istatistiksel orta noktasina en yakin dusen sinif
# oldugu icin, tum "notr" test girdileri yanlislikla Infiltration'a
# duruyordu.
#
# COZUM: Bu script, senin data/ klasorundeki AYNI CSV
# dosyalarini (layer1.ipynb'nin okudugu ayni dosyalar) okuyup,
# HER SINIF ICIN AYRI AYRI medyan degerlerini hesaplar ve
# diske kaydeder (models/layer1_class_medians.joblib).
#
# run_pipeline.py, artik "genel medyan" yerine "hedeflenen
# sinifin GERCEK medyan vektorunu" taban olarak kullanabilir -
# boylece test flow'u GERCEKTEN o sinifin tipik davranisina
# benzer hale gelir, sadece bilerek override ettigimiz alanlar
# (payload gibi) farklilasir.
#
# NASIL CALISTIRILIR?
# ------------------------------------------------------------
#   python compute_class_medians.py
#
# Bu script, layer1.ipynb ile AYNI klasorde (yani data/ ve
# models/ klasorlerinin gorunebildigi yerde) calistirilmalidir.
# Model egitmez, SADECE CSV'leri okuyup medyan hesaplar - bu
# yuzden layer1.ipynb'den cok daha hizli calisir.
# ============================================================

import os
import re
import gc
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


def log(*args):
    print(*args, flush=True)


# ============================================================
# 1. DOSYA YOLLARI (layer1.ipynb ile AYNI olmali)
# ============================================================

DATA_DIR = "data"
MODEL_DIR = "models"
OUTPUT_DIR = "outputs"

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

LAYER1_MODEL_PATH = os.path.join(MODEL_DIR, "attack_classifier.joblib")
CLASS_MEDIANS_PATH = os.path.join(MODEL_DIR, "layer1_class_medians.joblib")
CLASS_MEDIANS_CSV_DEBUG_PATH = os.path.join(OUTPUT_DIR, "layer1_class_medians_debug.csv")

CICIDS_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

CSE_CIC_IDS_2018_INFILTRATION_FILE = os.path.join(DATA_DIR, "Wednesday-28-02-2018.csv")

CSE_CIC_IDS_2018_WEBATTACK_FILES = [
    os.path.join(DATA_DIR, "SQL Injection.csv"),
    os.path.join(DATA_DIR, "Brute Force -Web.csv"),
    os.path.join(DATA_DIR, "Brute Force -XSS.csv"),
]

WEB_ATTACK_CANDIDATE_LABEL = "WebAttackCandidate"


# ============================================================
# 2. KOLON ESLEME (layer1.ipynb ile BIREBIR AYNI)
# ============================================================

COLUMN_MAPPING_2018_TO_2017 = {
    "Dst Port": "Destination Port",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward"
}


# ============================================================
# 3. LABEL NORMALIZASYONU (layer1.ipynb ile BIREBIR AYNI)
# ============================================================

def normalize_label(label):

    label = str(label).strip()
    label = re.sub(r"\s+", " ", label)

    label = (
        label
        .replace("ï¿½", "-")
        .replace("�", "-")
        .replace("–", "-")
        .replace("—", "-")
    )

    lower_label = label.casefold()

    if lower_label == "label":
        return "HEADER_ROW"

    if lower_label == "benign":
        return "BENIGN"

    if "web attack" in lower_label:
        return WEB_ATTACK_CANDIDATE_LABEL

    explicit_web_labels = {
        "brute force -web", "brute force - web",
        "brute force -xss", "brute force - xss",
        "sql injection", "sql-injection", "sqli",
        "xss", "cross site scripting", "cross-site scripting"
    }

    if lower_label in explicit_web_labels:
        return WEB_ATTACK_CANDIDATE_LABEL

    compact_label = re.sub(r"[\s_\-]+", "", lower_label)

    compact_web_labels = {
        "webattackbruteforce", "webattackxss", "webattacksqlinjection",
        "bruteforceweb", "bruteforcexss", "sqlinjection", "sqli",
        "xss", "crosssitescripting"
    }

    if compact_label in compact_web_labels:
        return WEB_ATTACK_CANDIDATE_LABEL

    if lower_label in {"infilteration", "infiltration"}:
        return "Infiltration"

    if "ftp" in lower_label and "patator" in lower_label:
        return "FTP-Patator"
    if "ssh" in lower_label and "patator" in lower_label:
        return "SSH-Patator"
    if "ftp" in lower_label and "brute" in lower_label:
        return "FTP-BruteForce"
    if "ssh" in lower_label and "brute" in lower_label:
        return "SSH-BruteForce"

    if lower_label in {"bot", "botnet"}:
        return "Botnet"

    if lower_label in {"portscan", "port scan"}:
        return "PortScan"

    if lower_label == "ddos":
        return "DDoS"

    if "ddos" in lower_label:
        if "hoic" in lower_label:
            return "DDoS-HOIC"
        if "loic" in lower_label and "udp" in lower_label:
            return "DDoS-LOIC-UDP"
        if "loic" in lower_label:
            return "DDoS-LOIC-HTTP"
        return "DDoS"

    if "slowhttptest" in lower_label:
        return "DoS Slowhttptest"
    if "slowloris" in lower_label:
        return "DoS slowloris"
    if "goldeneye" in lower_label:
        return "DoS GoldenEye"
    if "hulk" in lower_label:
        return "DoS Hulk"

    return label


# ============================================================
# 4. CSV OKUMA (layer1.ipynb ile AYNI mantik, SADELESTIRILMIS)
# ============================================================

def load_and_prepare_csv(file_path, dataset_name):

    log("Dosya okunuyor:", file_path, "(", dataset_name, ")")

    if not os.path.exists(file_path):
        log("  UYARI: Dosya bulunamadi, atlandi.")
        return None

    df = pd.read_csv(file_path, low_memory=False)
    df.columns = df.columns.astype(str).str.strip()

    if "Label" not in df.columns:
        log("  UYARI: Label kolonu bulunamadi, atlandi.")
        return None

    applicable_mapping = {
        old_name: new_name
        for old_name, new_name in COLUMN_MAPPING_2018_TO_2017.items()
        if old_name in df.columns and new_name not in df.columns
    }

    if applicable_mapping:
        df.rename(columns=applicable_mapping, inplace=True)

    df["_original_label"] = df["Label"].astype(str).str.strip()

    heartbleed_mask = df["_original_label"].str.contains("heartbleed", case=False, na=False)

    if heartbleed_mask.any():
        df = df[~heartbleed_mask].copy()

    df["Label"] = df["Label"].apply(normalize_label)
    df = df[df["Label"] != "HEADER_ROW"].copy()
    df = df[df["Label"] != "BENIGN"].copy()

    if df.empty:
        return None

    log(f"  Kalan kayit sayisi: {len(df)} | Siniflar: {df['Label'].value_counts().to_dict()}")

    return df


# ============================================================
# 5. TUM DOSYALARI YUKLE VE BIRLESTIR
# ============================================================

log("=" * 80)
log("SINIF-BAZLI MEDYAN HESAPLAMA BASLIYOR")
log("=" * 80)

if not os.path.exists(LAYER1_MODEL_PATH):
    raise FileNotFoundError(
        f"Layer 1 modeli bulunamadi: {LAYER1_MODEL_PATH}\n"
        "Once layer1.ipynb notebook'unu calistirip modelin "
        "egitilmis/kaydedilmis oldugundan emin olun (bu script, "
        "modelin bekledigi TAM feature listesini oradan okur)."
    )

log("\nLayer 1 model bundle'i yukleniyor (feature listesi icin)...")
layer1_bundle = joblib.load(LAYER1_MODEL_PATH)
model_features = layer1_bundle["features"]

log(f"Model {len(model_features)} feature bekliyor.")

attack_frames = []

log("\n--- CICIDS2017 dosyalari ---")
for file_name in CICIDS_FILES:
    file_path = os.path.join(DATA_DIR, file_name)
    prepared_df = load_and_prepare_csv(file_path, "CICIDS2017")
    if prepared_df is not None:
        attack_frames.append(prepared_df)

log("\n--- CSE-CIC-IDS2018 Infiltration ---")
infiltration_df = load_and_prepare_csv(CSE_CIC_IDS_2018_INFILTRATION_FILE, "CSE-CIC-IDS2018")
if infiltration_df is not None:
    infiltration_df = infiltration_df[infiltration_df["Label"] == "Infiltration"].copy()
    if not infiltration_df.empty:
        attack_frames.append(infiltration_df)

log("\n--- CSE-CIC-IDS2018 Web Attacks (opsiyonel) ---")
for web_file in CSE_CIC_IDS_2018_WEBATTACK_FILES:
    web_df = load_and_prepare_csv(web_file, "CSE-CIC-IDS2018-WebAttacks")
    if web_df is not None:
        web_df = web_df[web_df["Label"] == WEB_ATTACK_CANDIDATE_LABEL].copy()
        if not web_df.empty:
            attack_frames.append(web_df)

if not attack_frames:
    raise ValueError("Hicbir dosya yuklenemedi. DATA_DIR icerigini kontrol edin.")

attack_df = pd.concat(attack_frames, ignore_index=True, sort=False)
del attack_frames
gc.collect()

log("\n" + "=" * 80)
log("Toplam yuklenen kayit:", len(attack_df))
log("Sinif dagilimi:")
log(attack_df["Label"].value_counts())


# ============================================================
# 6. FEATURE'LARI SAYISALLASTIR (model_features ile HIZALA)
# ============================================================

available_features = [f for f in model_features if f in attack_df.columns]
missing_features = [f for f in model_features if f not in attack_df.columns]

if missing_features:
    log(
        f"\nUYARI: Modelin bekledigi {len(missing_features)} feature "
        f"bu veri setinde bulunamadi (medyan hesaplanamayacak, "
        f"run_pipeline.py bunlar icin genel imputer medyanina "
        f"donecek): {missing_features}"
    )

X = attack_df[available_features].copy()

for col in available_features:
    X[col] = pd.to_numeric(X[col], errors="coerce").astype("float64")

X.replace([np.inf, -np.inf], np.nan, inplace=True)

X["Label"] = attack_df["Label"].to_numpy()


# ============================================================
# 7. SINIF BAZINDA MEDYAN HESAPLA
# ============================================================

log("\n" + "=" * 80)
log("SINIF BAZINDA MEDYAN HESAPLANIYOR")
log("=" * 80)

class_medians = {}

for class_name, group in X.groupby("Label"):

    medians = group[available_features].median(numeric_only=True)

    full_median_dict = {feature: float(medians.get(feature, np.nan)) for feature in model_features}

    class_medians[class_name] = full_median_dict

    log(f"  {class_name}: {len(group)} kayit uzerinden medyan hesaplandi.")

joblib.dump(class_medians, CLASS_MEDIANS_PATH)

log("\nSinif medyanlari kaydedildi:", CLASS_MEDIANS_PATH)

medians_df = pd.DataFrame(class_medians).transpose()
medians_df.to_csv(CLASS_MEDIANS_CSV_DEBUG_PATH)
log("Okunabilir CSV (debug amacli) kaydedildi:", CLASS_MEDIANS_CSV_DEBUG_PATH)

log("\n" + "=" * 80)
log("TAMAMLANDI")
log("=" * 80)
log(
    "\nArtik run_pipeline.py, her test senaryosu icin GENEL "
    "medyan yerine HEDEFLENEN SINIFIN GERCEK medyan vektorunu "
    "taban olarak kullanabilir. run_pipeline.py'yi TEKRAR "
    "CALISTIRMADAN ONCE bu script'in basariyla tamamlandigindan "
    "emin olun."
)