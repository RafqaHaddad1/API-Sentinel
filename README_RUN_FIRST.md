# API Sentinel — Clean Final Structure

## Run everything

Open terminal inside this folder and run:

```bash
pip install -r requirements.txt
python run_system.py
```

Then open:

- Dashboard: http://127.0.0.1:5000
- Proxy/API security layer: http://127.0.0.1:8000
- Dummy backend: http://127.0.0.1:8001

## Final flow

```text
Client request → FastAPI proxy on port 8000 → ML pipeline → SQLite DB → Flask dashboard on port 5000
                                      ↓
                              Dummy backend on port 8001
```

## Main files

- `run_system.py` → starts everything
- `backend/api.py` → FastAPI proxy and logging
- `backend/pipeline.py` → model-based detection decision
- `backend/feature_extraction.py` → same request feature builder used by training/runtime
- `dashboard/app.py` → Flask dashboard
- `training/API_Sentinel_Training_Only.ipynb` → training only
- `models/` → trained model artifacts
- `sam_ads.db` → one database used by both proxy and dashboard

## Important rule

Do not run the full original notebook as the app anymore. Use the notebook only for retraining and saving models.
