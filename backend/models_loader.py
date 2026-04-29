import json
import joblib
from settings import MODELS_DIR

rf_model = joblib.load(MODELS_DIR / "rf_model.pkl")
iso_model = joblib.load(MODELS_DIR / "iso_model.pkl")
feature_columns = joblib.load(MODELS_DIR / "feature_columns.pkl")
rf_threshold = joblib.load(MODELS_DIR / "rf_threshold.pkl")
iso_threshold = joblib.load(MODELS_DIR / "iso_threshold.pkl")

registry_path = MODELS_DIR / "model_registry.json"
if registry_path.exists():
    with open(registry_path, "r", encoding="utf-8") as f:
        model_registry = json.load(f)
else:
    model_registry = {
        "random_forest": {"version": "rf_v1", "threshold": float(rf_threshold), "feature_file": "feature_columns.pkl"},
        "isolation_forest": {"version": "iso_v1", "threshold": float(iso_threshold)},
        "session_behavior": {"version": "session_behavior_v1", "threshold": 25.0},
    }
