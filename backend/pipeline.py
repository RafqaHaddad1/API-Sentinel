import hashlib
import json
import time
from collections import defaultdict, deque

import pandas as pd

from backend.feature_extraction import build_request_features
from backend.models_loader import feature_columns, iso_model, iso_threshold, model_registry, rf_model, rf_threshold
from backend.rule_engine import RuleBasedDetectionEngine

rule_engine = RuleBasedDetectionEngine()

SESSION_STORE = defaultdict(lambda: {
    "first_seen": None,
    "last_seen": None,
    "ip_history": deque(maxlen=10),
    "user_agent_history": deque(maxlen=10),
    "endpoint_history": deque(maxlen=20),
    "request_fingerprints": deque(maxlen=50),
    "fingerprint_times": {},
    "replay_count": 0,
    "hijack_score": 0.0,
})

REPLAY_WINDOW_SECONDS = 60
SEQUENCE_WINDOW = 5

def hash_token(token):
    if not token:
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def build_session_id(headers: dict, client_ip: str):
    auth_token = headers.get("authorization")
    cookie = headers.get("cookie", "")
    user_agent = headers.get("user-agent", "")
    token_hash = hash_token(auth_token)
    if token_hash:
        return f"token::{token_hash}"
    if cookie:
        cookie_hash = hashlib.sha256(cookie.encode("utf-8")).hexdigest()
        return f"cookie::{cookie_hash}"
    fallback = f"{client_ip}|{user_agent}"
    return f"anon::{hashlib.sha256(fallback.encode('utf-8')).hexdigest()}"

def build_request_fingerprint(method, path, query_params, body_text, token_hash):
    raw = json.dumps({"method": method, "path": path, "query_params": query_params, "body_text": body_text, "token_hash": token_hash}, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def extract_features(body_text: str, query_params: dict, headers: dict, method: str, path: str):
    feats = build_request_features(
        path=path,
        payload=body_text,
        query_params=query_params,
        headers=headers,
        method=method,
        user_agent=headers.get("user-agent", ""),
    )
    row = {c: feats.get(c, 0) for c in feature_columns}
    X_live = pd.DataFrame([row])[feature_columns].fillna(0)
    return X_live, feats

def analyze_session_behavior(session_id, token_hash, client_ip, user_agent, method, path, query_params, body_text):
    now = time.time()
    session = SESSION_STORE[session_id]
    if session["first_seen"] is None:
        session["first_seen"] = now
    session["last_seen"] = now

    request_fingerprint = build_request_fingerprint(method, path, query_params, body_text, token_hash)
    replay_flag = 0
    ip_changed = 0
    user_agent_changed = 0
    sequence_anomaly = 0
    hijack_score = 0.0
    mitm_reasons = []

    if request_fingerprint in session["fingerprint_times"]:
        last_seen = session["fingerprint_times"][request_fingerprint]
        if now - last_seen <= REPLAY_WINDOW_SECONDS:
            replay_flag = 1
            session["replay_count"] += 1
            hijack_score += 35.0
            mitm_reasons.append("replayed request fingerprint within short time window")

    session["fingerprint_times"][request_fingerprint] = now
    session["request_fingerprints"].append(request_fingerprint)

    if len(session["ip_history"]) > 0 and client_ip not in session["ip_history"]:
        ip_changed = 1
        hijack_score += 20.0
        mitm_reasons.append("session used from new ip")
    session["ip_history"].append(client_ip)

    if len(session["user_agent_history"]) > 0 and user_agent not in session["user_agent_history"]:
        user_agent_changed = 1
        hijack_score += 20.0
        mitm_reasons.append("session used from new user-agent")
    session["user_agent_history"].append(user_agent)

    sensitive_keywords = ["admin", "delete", "update", "config", "users", "export"]
    recent_endpoints = list(session["endpoint_history"])
    if any(k in path.lower() for k in sensitive_keywords):
        if len(recent_endpoints) == 0:
            sequence_anomaly = 1
            hijack_score += 20.0
            mitm_reasons.append("sensitive endpoint accessed without prior session flow")
        elif len(recent_endpoints) >= 2 and path not in recent_endpoints[-SEQUENCE_WINDOW:]:
            sequence_anomaly = 1
            hijack_score += 15.0
            mitm_reasons.append("abrupt endpoint jump in session flow")

    session["endpoint_history"].append(path)
    session["hijack_score"] = hijack_score
    mitm_behavior_class = "malicious" if hijack_score >= 60 else ("suspicious" if hijack_score >= 25 else "normal")

    return {
        "session_id": session_id,
        "request_fingerprint": request_fingerprint,
        "replay_flag": replay_flag,
        "replay_count": session["replay_count"],
        "ip_changed": ip_changed,
        "user_agent_changed": user_agent_changed,
        "sequence_anomaly": sequence_anomaly,
        "hijack_score": hijack_score,
        "mitm_behavior_class": mitm_behavior_class,
        "mitm_reasons": mitm_reasons,
    }

def default_rule_result():
    return {"decision": "allow", "label": "normal", "risk_score": 0.0, "reasons": []}

def predict_request(X_live, features, headers, body_text, method, path, query_params, client_ip):
    user_agent = headers.get("user-agent", "") or ""
    auth_token = headers.get("authorization")
    token_hash = hash_token(auth_token)
    session_id = build_session_id(headers, client_ip)

    has_strong_signal = (
        features.get("sql_pattern_hits", 0) > 0
        or features.get("xss_pattern_hits", 0) > 0
        or features.get("cmd_pattern_hits", 0) > 0
        or features.get("traversal_pattern_hits", 0) > 0
        or features.get("bad_ua_pattern_hits", 0) > 0
    )
    sql_keywords_weak = ["select", "union", "drop", "insert", "delete", "update"]
    combined_text = f"{path} {body_text} {' '.join(str(v) for v in (query_params or {}).values())}".lower()
    has_weak_keyword = any(k in combined_text for k in sql_keywords_weak)
    has_weak_signal = features.get("special_char_count", 0) >= 1 or features.get("percent_count", 0) >= 2 or has_weak_keyword
    no_attack_indicators = not has_strong_signal and not has_weak_signal

    try:
        classes = list(rf_model.classes_)
        idx = classes.index(1) if 1 in classes else 1
        rf_score = float(rf_model.predict_proba(X_live)[0][idx])
    except Exception:
        rf_score = 0.0

    if no_attack_indicators:
        rf_score = 0.0
    elif has_weak_signal and not has_strong_signal:
        rf_score = max(0.50, min(rf_score, 0.55))

    try:
        iso_raw = float(-iso_model.score_samples(X_live)[0])
    except Exception:
        iso_raw = 0.0
    iso_flag = int(iso_raw >= iso_threshold) and not no_attack_indicators
    iso_norm = max(0.0, min(iso_raw / (float(iso_threshold) + 1e-9), 1.0))
    if no_attack_indicators:
        iso_norm = 0.0

    rule_result = rule_engine.evaluate_request({
        "client_ip": client_ip, "method": method, "path": path,
        "query_params": query_params, "headers": headers, "body": body_text,
    }) or default_rule_result()
    rule_decision = str(rule_result.get("decision", "allow")).lower()
    rule_risk_norm = max(0.0, min(float(rule_result.get("risk_score", 0)) / 100.0, 1.0))
    rule_block = rule_decision == "block"

    session_data = analyze_session_behavior(session_id, token_hash, client_ip, user_agent, method, path, query_params, body_text)
    replay_flag = int(session_data.get("replay_flag", 0))
    hijack_score = float(session_data.get("hijack_score", 0.0))
    mitm_norm = min(hijack_score / 100.0, 1.0)
    mitm_class = "malicious" if hijack_score >= 60 else ("suspicious" if hijack_score >= 25 or replay_flag else "normal")

    final_score = max(0.0, min(0.60 * rf_score + 0.15 * iso_norm + 0.15 * mitm_norm + 0.10 * rule_risk_norm, 1.0))
    if has_weak_signal and not has_strong_signal:
        final_score = max(final_score, 0.55)
    if rule_block and rf_score >= 0.30:
        final_score = max(final_score, 0.75)
    if mitm_class == "malicious" and rf_score >= 0.30:
        final_score = max(final_score, 0.75)

    block_threshold = 0.70
    flag_threshold = 0.50
    if final_score >= block_threshold:
        predicted_class, decision = "malicious", "block"
    elif final_score >= flag_threshold:
        predicted_class, decision = "suspicious", "flag"
    else:
        predicted_class, decision = "normal", "allow"

    reasons = []
    if no_attack_indicators:
        reasons.append("no attack indicators present (model bypassed)")
    elif has_weak_signal and not has_strong_signal:
        reasons.append("weak attack signal detected")
    if rf_score >= 0.70:
        reasons.append(f"random forest confident attack (p={rf_score:.2f})")
    elif rf_score >= 0.50:
        reasons.append(f"random forest moderate attack signal (p={rf_score:.2f})")
    if rule_block:
        reasons.extend(rule_result.get("reasons", [])[:2])
    if iso_flag:
        reasons.append("isolation forest anomaly detected")
    if replay_flag:
        reasons.append("request replay detected")
    if mitm_class != "normal":
        reasons.append(f"session behavior {mitm_class} (hijack={hijack_score:.0f})")

    return {
        "decision": decision,
        "reason": "; ".join(dict.fromkeys(reasons)) if reasons else "normal request",
        "predicted_class": predicted_class,
        "confidence": float(final_score),
        "risk_score": float(final_score),
        "supervised_score": float(rf_score),
        "anomaly_flag": int(iso_flag),
        "iso_score": float(iso_raw),
        "iso_score_norm": float(iso_norm),
        "mitm_class": mitm_class,
        "mitm_score": float(mitm_norm),
        "rule_score": float(rule_risk_norm),
        "rule_result": rule_result,
        "session_data": session_data,
        "token_hash": token_hash,
        "session_id": session_id,
        "model_versions": {
            "random_forest_version": model_registry.get("random_forest", {}).get("version", "rf_v3_with_guard"),
            "isolation_forest_version": model_registry.get("isolation_forest", {}).get("version", "iso_v3_with_guard"),
            "session_behavior_version": model_registry.get("session_behavior", {}).get("version", "session_v3"),
        },
        "model_thresholds": {
            "rf_threshold": float(rf_threshold), "iso_threshold": float(iso_threshold),
            "flag_threshold": flag_threshold, "block_threshold": block_threshold,
        },
    }
