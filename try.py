import joblib
import pandas as pd

bundle = joblib.load("models/attack_classifier.joblib")

features = bundle["features"]

row = {
    f: bundle["imputer"].statistics_[i]
    for i, f in enumerate(features)
}

df = pd.DataFrame([row])

pred = bundle["model"].predict(df)[0]

print(
    bundle["label_encoder"].inverse_transform([pred])[0]
)