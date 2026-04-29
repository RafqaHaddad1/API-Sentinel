import csv
import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from backend.email_alert_service import send_email_alert, map_severity
import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from backend.models_loader import model_registry
from backend.pipeline import extract_features, hash_token, predict_request
from settings import BACKEND_BASE_URL, CSV_LOG_PATH, DB_PATH, REQUEST_TIMEOUT

app = FastAPI(title="API Sentinel Proxy")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
logs = []

def filter_request_headers(headers: dict) -> dict:
    excluded = {"host", "content-length", "connection"}
    return {k: v for k, v in headers.items() if k.lower() not in excluded}

def filter_response_headers(headers: dict) -> dict:
    excluded = {"content-encoding", "transfer-encoding", "connection"}
    return {k: v for k, v in headers.items() if k.lower() not in excluded}

def should_trigger_alert(log_entry):
    return (
        log_entry.get("predicted_class") in ("malicious", "suspicious")
        or int(log_entry.get("replay_flag", 0)) == 1
        or float(log_entry.get("hijack_score", 0.0)) >= 50.0
    )

def save_alert(log_entry):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO alerts (log_id, timestamp, ip_address, path, attack_type, severity, decision, message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log_entry["id"], log_entry["timestamp"], log_entry["ip_address"], log_entry["path"],
                log_entry["predicted_class"], "HIGH" if log_entry["predicted_class"] == "malicious" else "MEDIUM",
                log_entry["decision"], log_entry["reason"],
            ),
        )
        conn.commit()
    except Exception as exc:
        print("save_alert error:", exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass

def save_log_to_csv(log_entry):
    CSV_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    row = {k: log_entry.get(k) for k in [
        "id", "timestamp", "ip_address", "method", "path", "backend_url", "user_agent", "authorization",
        "token_hash", "cookie", "content_length", "response_time_ms", "response_status", "decision", "reason",
        "predicted_class", "label", "supervised_score", "anomaly_flag", "iso_score", "mitm_class", "mitm_score",
        "rule_decision", "rule_label", "rule_risk_score", "fusion_confidence", "fusion_risk_score", "rf_model_version",
        "iso_model_version", "session_behavior_version", "rf_threshold", "iso_threshold", "feature_file", "session_id",
        "request_fingerprint", "replay_flag", "replay_count", "ip_changed", "user_agent_changed", "sequence_anomaly",
        "hijack_score"
    ]}
    row["query_params"] = json.dumps(log_entry.get("query_params", {}))
    row["headers"] = json.dumps(log_entry.get("headers", {}))
    row["payload"] = log_entry.get("payload")
    row["extracted_features"] = json.dumps(log_entry.get("extracted_features", {}))
    row["rule_reasons"] = json.dumps(log_entry.get("rule_reasons", []))
    row["mitm_reasons"] = json.dumps(log_entry.get("mitm_reasons", []))
    file_exists = CSV_LOG_PATH.exists()
    with open(CSV_LOG_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

def save_log_to_sqlite(log_entry):
    columns = [
        "id", "timestamp", "ip_address", "method", "path", "backend_url", "headers", "payload", "query_params",
        "user_agent", "authorization", "token_hash", "cookie", "content_length", "response_time_ms", "response_status",
        "decision", "reason", "predicted_class", "supervised_score", "anomaly_flag", "iso_score", "label",
        "extracted_features", "mitm_class", "mitm_score", "rule_decision", "rule_label", "rule_risk_score",
        "rule_reasons", "fusion_confidence", "fusion_risk_score", "rf_model_version", "iso_model_version",
        "session_behavior_version", "rf_threshold", "iso_threshold", "feature_file", "session_id", "request_fingerprint",
        "replay_flag", "replay_count", "ip_changed", "user_agent_changed", "sequence_anomaly", "hijack_score", "mitm_reasons",
    ]
    values = []
    for c in columns:
        val = log_entry.get(c)
        if c in {"headers", "query_params", "extracted_features", "rule_reasons", "mitm_reasons"}:
            val = json.dumps(val if val is not None else ([] if c.endswith("reasons") else {}))
        values.append(val)
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        placeholders = ", ".join(["?"] * len(columns))
        cur.execute(f"INSERT INTO api_logs ({', '.join(columns)}) VALUES ({placeholders})", values)
        conn.commit()
    except Exception as exc:
        print("SQLite error:", exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass

@app.get("/")
async def root():
    return {"message": "SAM-ADS proxy is running", "backend": BACKEND_BASE_URL}

@app.get("/logs")
async def get_logs():
    return {"total_logs": len(logs), "logs": logs[-100:]}

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(path: str, request: Request):
    start_time = time.time()
    body = await request.body()
    body_text = body.decode("utf-8", errors="ignore")
    query_params = dict(request.query_params)
    headers = dict(request.headers)
    client_ip = request.client.host if request.client else "unknown"
    target_url = f"{BACKEND_BASE_URL.rstrip('/')}/{path}"

    X_live, features = extract_features(body_text, query_params, headers, request.method, path)
    prediction = predict_request(X_live, features, headers, body_text, request.method, path, query_params, client_ip)
    rule_result = prediction["rule_result"]
    session_data = prediction["session_data"]

    log_entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip_address": client_ip,
        "method": request.method,
        "path": f"/{path}",
        "backend_url": target_url,
        "headers": headers,
        "payload": body_text,
        "query_params": query_params,
        "user_agent": headers.get("user-agent"),
        "authorization": headers.get("authorization"),
        "token_hash": prediction["token_hash"],
        "cookie": headers.get("cookie"),
        "content_length": len(body),
        "response_time_ms": None,
        "response_status": None,
        "decision": prediction["decision"],
        "reason": prediction["reason"],
        "predicted_class": prediction["predicted_class"],
        "label": prediction["predicted_class"],
        "supervised_score": float(prediction["supervised_score"]),
        "anomaly_flag": int(prediction["anomaly_flag"]),
        "iso_score": float(prediction["iso_score"]),
        "extracted_features": features,
        "mitm_class": prediction["mitm_class"],
        "mitm_score": float(prediction["mitm_score"]),
        "rule_decision": rule_result.get("decision"),
        "rule_label": rule_result.get("label"),
        "rule_risk_score": rule_result.get("risk_score"),
        "rule_reasons": rule_result.get("reasons", []),
        "fusion_confidence": prediction["confidence"],
        "fusion_risk_score": prediction["risk_score"],
        "rf_model_version": prediction["model_versions"]["random_forest_version"],
        "iso_model_version": prediction["model_versions"]["isolation_forest_version"],
        "session_behavior_version": prediction["model_versions"]["session_behavior_version"],
        "rf_threshold": prediction["model_thresholds"]["rf_threshold"],
        "iso_threshold": prediction["model_thresholds"]["iso_threshold"],
        "feature_file": model_registry.get("random_forest", {}).get("feature_file", "feature_columns.pkl"),
        "session_id": session_data["session_id"],
        "request_fingerprint": session_data["request_fingerprint"],
        "replay_flag": int(session_data["replay_flag"]),
        "replay_count": int(session_data["replay_count"]),
        "ip_changed": int(session_data["ip_changed"]),
        "user_agent_changed": int(session_data["user_agent_changed"]),
        "sequence_anomaly": int(session_data["sequence_anomaly"]),
        "hijack_score": float(session_data["hijack_score"]),
        "mitm_reasons": session_data["mitm_reasons"],
    }

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            backend_response = await client.request(
                method=request.method,
                url=target_url,
                headers=filter_request_headers(headers),
                params=query_params,
                content=body,
            )
        log_entry["response_status"] = backend_response.status_code
        content = backend_response.content
        status = backend_response.status_code
        response_headers = filter_response_headers(dict(backend_response.headers))
        media_type = backend_response.headers.get("content-type")
    except httpx.RequestError as exc:
        log_entry["response_status"] = 502
        log_entry["decision"] = "error"
        log_entry["reason"] = f"backend forwarding failed: {str(exc)}"
        content = json.dumps({"message": "Backend request failed", "decision": "error", "reason": str(exc)}).encode("utf-8")
        status = 502
        response_headers = {}
        media_type = "application/json"

    log_entry["response_time_ms"] = round((time.time() - start_time) * 1000, 2)
    logs.append(log_entry)
    save_log_to_csv(log_entry)
    save_log_to_sqlite(log_entry)
    if should_trigger_alert(log_entry):
        try:
            save_alert(log_entry)
        except Exception as e:
            print("Alert save error:", e)

        alert_message = f"""
    API SECURITY ALERT
    IP: {log_entry.get("ip_address")}
    Endpoint: {log_entry.get("path")}
    Method: {log_entry.get("method")}
    Class: {log_entry.get("predicted_class")}
    Decision: {log_entry.get("decision")}
    Replay: {log_entry.get("replay_flag")}
    Hijack Score: {log_entry.get("hijack_score")}
    Risk Score: {log_entry.get("fusion_risk_score")}
    Reason: {log_entry.get("reason")}
    """
        try:
            send_email_alert(
                subject="API Sentinel Alert",
                body=alert_message,
                severity=map_severity(log_entry.get("predicted_class")),
                trigger=log_entry.get("reason", ""),
                ip_address=log_entry.get("ip_address", ""),
                endpoint=log_entry.get("path", ""),
                method=log_entry.get("method", ""),
                status_code=log_entry.get("response_status", ""),
                user_agent=log_entry.get("user_agent", ""),
                risk_score=log_entry.get("fusion_risk_score", 0.0),
            )
        except Exception as e:
            print("Email alert error:", e)
    print("=== Security Log Entry ===")
    print(json.dumps(log_entry, indent=2, default=str))

    return Response(content=content, status_code=status, headers=response_headers, media_type=media_type)
