from flask import Blueprint, jsonify, request
from urllib.parse import urlparse, parse_qs
import re

from utils import json_error

# IMPORTANT: change this import to match your real pipeline file/function name
# Example options:
# from pipeline import run_security_pipeline
# from detection_pipeline import run_pipeline
from backend.pipeline import predict_request
from backend.pipeline import extract_features
url_scanner_bp = Blueprint("url_scanner", __name__)


def extract_url_features(url):
    parsed = urlparse(url)

    url_lower = url.lower()
    hostname = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    suspicious_keywords = [
        "select", "union", "drop", "script", "<script", "../", "..\\",
        "cmd", "exec", "token", "passwd", "admin", "login", "%3cscript%3e"
    ]

    features = {
        "url": url,
        "method": "GET",
        "path": parsed.path or "/",
        "query_params": parsed.query,
        "payload": "",
        "headers": {},
        "user_agent": "URL Scanner",

        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "has_ip_in_host": int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname.split(":")[0]))),
        "has_at_symbol": int("@" in url),
        "has_double_slash_in_path": int("//" in path),
        "has_encoded_chars": int("%" in url),
        "query_param_count": len(parse_qs(parsed.query)),
        "suspicious_keyword_count": sum(1 for keyword in suspicious_keywords if keyword in url_lower),
        "uses_https": int(parsed.scheme == "https"),
    }

    return features

@url_scanner_bp.route("/api/scan-url", methods=["POST"])
def scan_url():
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()

        if not url:
            return json_error("URL is required", 400)

        parsed = urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            return json_error("Invalid URL format", 400)

        # --- Prepare inputs for pipeline ---
        method = "GET"
        path = parsed.path or "/"
        query_params = dict(parse_qs(parsed.query))
        body_text = ""
        headers = {"user-agent": "URL Scanner"}
        client_ip = "0.0.0.0"  # dummy IP for scanner

        # --- Extract ML features (IMPORTANT) ---
        X_live, features = extract_features(
            body_text=body_text,
            query_params=query_params,
            headers=headers,
            method=method,
            path=path
        )

        # --- Run pipeline correctly ---
        pipeline_result = predict_request(
            X_live,
            features,
            headers,
            body_text,
            method,
            path,
            query_params,
            client_ip
        )

        predicted_class = pipeline_result.get("predicted_class", "normal")

        verdict = {
            "normal": "Safe",
            "suspicious": "Suspicious",
            "malicious": "Malicious"
        }.get(predicted_class.lower(), predicted_class)

        return jsonify({
            "success": True,
            "url": url,
            "predicted_class": predicted_class,
            "verdict": verdict,
            "confidence_score": pipeline_result.get("confidence", 0),
            "reason": pipeline_result.get("reason", ""),
            "pipeline_result": pipeline_result
        })

    except Exception as e:
        return json_error("Unexpected error while scanning URL", 500, e)