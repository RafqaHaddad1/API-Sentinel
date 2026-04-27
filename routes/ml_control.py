"""
routes/ml_control.py
====================
Thin proxy that forwards dashboard button clicks to the notebook's
FastAPI server on http://127.0.0.1:8000. The notebook owns all ML logic.

Endpoints exposed to the browser:
  POST /api/ml/run-pipeline           -> notebook /admin/run-pipeline
  POST /api/ml/retrain-unsupervised   -> notebook /admin/retrain
  GET  /api/ml/status                 -> notebook /admin/status
"""

from flask import Blueprint, jsonify
import requests

ml_control_bp = Blueprint("ml_control", __name__)

# The notebook runs uvicorn on this host/port (see the proxy startup cell).
NOTEBOOK_URL = "http://127.0.0.1:8000"
TIMEOUT = 10  # seconds — endpoints return immediately, jobs run in background


def _proxy(method: str, path: str):
    """Forward a request to the notebook and return its JSON response."""
    url = f"{NOTEBOOK_URL}{path}"
    try:
        if method == "POST":
            resp = requests.post(url, timeout=TIMEOUT)
        else:
            resp = requests.get(url, timeout=TIMEOUT)
    except requests.exceptions.ConnectionError:
        return jsonify({
            "success": False,
            "error": (
                "Cannot reach the notebook server on " + NOTEBOOK_URL +
                ". Make sure the notebook is running and the proxy cell "
                "has been executed."
            ),
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({
            "success": False,
            "error": f"Notebook server timed out after {TIMEOUT}s",
        }), 504

    # Pass the notebook's response straight through
    try:
        body = resp.json()
    except ValueError:
        body = {"success": False, "error": resp.text or "Empty response"}
    return jsonify(body), resp.status_code


@ml_control_bp.route("/api/ml/run-pipeline", methods=["POST"])
def run_pipeline():
    return _proxy("POST", "/admin/run-pipeline")


@ml_control_bp.route("/api/ml/retrain-unsupervised", methods=["POST"])
def retrain_unsupervised():
    return _proxy("POST", "/admin/retrain")


@ml_control_bp.route("/api/ml/status", methods=["GET"])
def status():
    return _proxy("GET", "/admin/status")