from flask import Blueprint, jsonify, request
import re
from urllib.parse import urlparse, parse_qs
from utils import json_error

url_scanner_bp = Blueprint("url_scanner", __name__)

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

        url_lower = url.lower()
        hostname = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()

        suspicious_keywords = [
            "select", "union", "drop", "script", "<script", "../", "..\\",
            "cmd", "exec", "token", "passwd", "admin", "login", "%3cscript%3e"
        ]

        reasons = []
        score = 0

        # Feature extraction
        features = {
            "url_length": len(url),
            "hostname_length": len(hostname),
            "path_length": len(path),
            "query_length": len(query),
            "has_ip_in_host": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname.split(":")[0])),
            "has_at_symbol": "@" in url,
            "has_double_slash_in_path": "//" in path,
            "has_encoded_chars": "%" in url,
            "query_param_count": len(parse_qs(parsed.query)),
            "suspicious_keyword_count": 0,
            "uses_https": parsed.scheme == "https"
        }

        for keyword in suspicious_keywords:
            if keyword in url_lower:
                features["suspicious_keyword_count"] += 1
                reasons.append(f"Contains suspicious pattern: {keyword}")
                score += 15

        if features["url_length"] > 120:
            reasons.append("Unusually long URL")
            score += 10

        if features["has_ip_in_host"]:
            reasons.append("Uses IP address instead of domain")
            score += 20

        if features["has_at_symbol"]:
            reasons.append("Contains @ symbol")
            score += 15

        if features["has_double_slash_in_path"]:
            reasons.append("Contains double slash in path")
            score += 10

        if features["has_encoded_chars"]:
            reasons.append("Contains encoded characters")
            score += 10

        if not features["uses_https"]:
            reasons.append("Does not use HTTPS")
            score += 5

        if "../" in url_lower or "..\\" in url_lower:
            reasons.append("Possible path traversal pattern")
            score += 25

        if "<script" in url_lower or "%3cscript%3e" in url_lower:
            reasons.append("Possible XSS pattern")
            score += 30

        if "union" in url_lower or "select" in url_lower or "drop" in url_lower:
            reasons.append("Possible SQL injection pattern")
            score += 30

        # Final classification
        if score >= 50:
            predicted_class = "malicious"
            verdict = "Malicious"
        elif score >= 20:
            predicted_class = "suspicious"
            verdict = "Suspicious"
        else:
            predicted_class = "normal"
            verdict = "Safe"

        confidence_score = min(round(score / 100, 2), 0.99)

        return jsonify({
            "success": True,
            "url": url,
            "predicted_class": predicted_class,
            "verdict": verdict,
            "confidence_score": confidence_score,
            "reason": "; ".join(reasons) if reasons else "No suspicious pattern detected",
            "features": features
        })

    except Exception as e:
        return json_error("Unexpected error while scanning URL", 500, e)
