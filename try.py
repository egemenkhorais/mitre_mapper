import joblib

artifact = joblib.load("models/payload_attack_classifier_v2.joblib")
print("Type of artifact:", type(artifact))

if isinstance(artifact, dict):
    print("Keys in dictionary:", artifact.keys())