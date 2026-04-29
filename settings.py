from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
DB_PATH = BASE_DIR / "sam_ads.db"
CSV_LOG_PATH = BASE_DIR / "outputs" / "sam_ads_logs.csv"
BACKEND_BASE_URL = "http://127.0.0.1:8001"
REQUEST_TIMEOUT = 30.0
