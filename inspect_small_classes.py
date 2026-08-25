# ============================================================
# KÜÇÜK SINIF TANI SCRIPTİ
# Pipeline'ı tekrar çalıştırmadan mevcut outputs/ dosyalarından
# Heartbleed, Infiltration, SSH-Patator gibi az örnekli
# sınıfların gerçek durumunu gösterir.
# ============================================================

import os
import pandas as pd

OUTPUT_DIR = "outputs"

REPORT_PATH = os.path.join(OUTPUT_DIR, "attack_classification_report_oof.csv")
PRED_PATH = os.path.join(OUTPUT_DIR, "attack_oof_predictions.csv")
INFIL_PATH = os.path.join(OUTPUT_DIR, "infiltration_performance_by_dataset.csv")

SMALL_CLASSES_OF_INTEREST = [
    "Heartbleed",
    "Infiltration",
    "SSH-Patator",
    "Web Attack - Sql Injection"
]

pd.set_option("display.width", 200)
pd.set_option("display.max_columns", 20)

# ------------------------------------------------------------
# 1. Sınıf bazlı OOF classification report
# ------------------------------------------------------------

if os.path.exists(REPORT_PATH):
    report_df = pd.read_csv(REPORT_PATH, index_col=0)

    print("=" * 80)
    print("SINIF BAZLI OOF CLASSIFICATION REPORT (ilgi çekici sınıflar)")
    print("=" * 80)

    existing = [c for c in SMALL_CLASSES_OF_INTEREST if c in report_df.index]
    print(report_df.loc[existing])

    print("\nTüm sınıflar (support'a göre artan sıralı):")
    print(report_df.sort_values("support").head(10))
else:
    print("UYARI:", REPORT_PATH, "bulunamadı.")


# ------------------------------------------------------------
# 2. Infiltration - dataset (2017 vs 2018) kırılımı
# ------------------------------------------------------------

if os.path.exists(INFIL_PATH):
    infil_df = pd.read_csv(INFIL_PATH)

    print("\n" + "=" * 80)
    print("INFILTRATION - DATASET (2017 vs 2018) KIRILIMI")
    print("=" * 80)
    print(infil_df)
else:
    print("\nUYARI:", INFIL_PATH, "bulunamadı (Infiltration sınıfı yoksa normal).")


# ------------------------------------------------------------
# 3. Yanlış tahmin edilen küçük-sınıf satırlarının detayı
#    (hangi sınıfla karıştırılmış, hangi kaynak dosyadan)
# ------------------------------------------------------------

if os.path.exists(PRED_PATH):
    pred_df = pd.read_csv(PRED_PATH)

    print("\n" + "=" * 80)
    print("KÜÇÜK SINIFLARDA YANLIŞ TAHMİN EDİLEN KAYITLAR")
    print("=" * 80)

    for cls in SMALL_CLASSES_OF_INTEREST:
        subset = pred_df[pred_df["true_attack"] == cls]

        if subset.empty:
            continue

        wrong = subset[~subset["is_correct"]]

        print(f"\n--- {cls} ---")
        print("Toplam örnek:", len(subset))
        print("Yanlış tahmin sayısı:", len(wrong))

        if not wrong.empty:
            print(
                wrong[
                    ["flow_id", "source_file", "dataset",
                     "predicted_attack", "confidence"]
                ].to_string(index=False)
            )
else:
    print("\nUYARI:", PRED_PATH, "bulunamadı.")

print("\nTanı scripti tamamlandı.")