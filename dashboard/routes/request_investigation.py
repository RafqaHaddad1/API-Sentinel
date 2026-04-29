import sqlite3
import json
from datetime import datetime
from flask import Blueprint, jsonify, request
from database import get_connection
from utils import json_error
import requests
request_investigation_bp = Blueprint("request_investigation", __name__)
from settings import BACKEND_BASE_URL, CSV_LOG_PATH, DB_PATH, REQUEST_TIMEOUT

# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────
def _try_parse_json(value):
    """Best-effort JSON parse. Returns {} for empty, original value if not JSON."""
    if value is None or value == "":
        return {}
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return value


def _derive_anomaly_verdict(anomaly_flag, mitm_class, predicted_class):
    """
    The schema has no `anomaly_verdict` column, so we derive one for the UI.
    Priority: explicit anomaly_flag → mitm_class → predicted_class → unknown.
    """
    if anomaly_flag is not None:
        try:
            return "anomalous" if int(anomaly_flag) == 1 else "normal"
        except (TypeError, ValueError):
            pass
    if mitm_class:
        return str(mitm_class).lower()
    if predicted_class:
        return str(predicted_class).lower()
    return "unknown"


# ──────────────────────────────────────────────────────────────────────────
# GET /api/request-details
# ──────────────────────────────────────────────────────────────────────────
@request_investigation_bp.route("/api/request-details", methods=["GET"])
def request_details():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        request_id = request.args.get("id", "").strip()
        if not request_id:
            return json_error("Missing request id", 400)

        cursor.execute("""
            SELECT
                id, timestamp, ip_address, method, path,
                headers, payload, query_params,
                predicted_class, reason,
                supervised_score, iso_score, anomaly_flag,
                mitm_class, mitm_score,
                rule_decision, rule_label, rule_risk_score, rule_reasons,
                fusion_confidence, fusion_risk_score,
                decision, label, extracted_features, response_time_ms,
                user_agent, content_length
            FROM api_logs
            WHERE id = ?
        """, (request_id,))
        row = cursor.fetchone()

        if not row:
            return json_error("Request not found", 404)

        row_dict = dict(row)
        predicted_class = (row_dict.get("predicted_class") or "").lower()

        # Build a useful "reason" that combines rule reasons + model reason
        reason_parts = []
        if row_dict.get("reason"):
            reason_parts.append(row_dict["reason"])
        if row_dict.get("rule_reasons"):
            rule_reasons_parsed = _try_parse_json(row_dict["rule_reasons"])
            if isinstance(rule_reasons_parsed, list):
                reason_parts.extend(str(r) for r in rule_reasons_parsed)
            elif isinstance(rule_reasons_parsed, str) and rule_reasons_parsed not in reason_parts:
                reason_parts.append(rule_reasons_parsed)
        reason = "; ".join([r for r in reason_parts if r]) or "No reason available"

        # Derive a verdict for the UI's "Anomaly Verdict" badge
        anomaly_verdict = _derive_anomaly_verdict(
            row_dict.get("anomaly_flag"),
            row_dict.get("mitm_class"),
            predicted_class,
        )

        # Decision: prefer stored decision, else derive from predicted_class
        decision = row_dict.get("decision")
        if not decision:
            if predicted_class == "malicious":
                decision = "block"
            elif predicted_class == "suspicious":
                decision = "flag"
            else:
                decision = "allow"

        # Features: prefer the model's own extracted_features blob, fall back to a synthesized one
        features = _try_parse_json(row_dict.get("extracted_features"))
        if not features or not isinstance(features, dict):
            features = {
                "method": row_dict.get("method", "-"),
                "path_length": len(row_dict.get("path") or ""),
                "payload_length": len(row_dict.get("payload") or ""),
                "has_query_params": 1 if row_dict.get("query_params") else 0,
                "has_headers": 1 if row_dict.get("headers") else 0,
                "content_length": row_dict.get("content_length") or 0,
                "response_time_ms": row_dict.get("response_time_ms") or 0,
                "user_agent": row_dict.get("user_agent") or "-",
            }

        # Confidence score: supervised_score (RF) is the right field; fall back to fusion_confidence
        confidence_score = row_dict.get("supervised_score")
        if confidence_score is None:
            confidence_score = row_dict.get("fusion_confidence")
        confidence_display = (
            f"{float(confidence_score):.3f}" if confidence_score is not None else "-"
        )

        iso_score = row_dict.get("iso_score")
        anomaly_display = (
            f"{float(iso_score):.3f}" if iso_score is not None else "-"
        )

        return jsonify({
            "success": True,
            "id": row_dict.get("id"),
            "timestamp": row_dict.get("timestamp", "-"),
            "ip_address": row_dict.get("ip_address", "-"),
            "method": row_dict.get("method", "-"),
            "path": row_dict.get("path", "-"),
            "headers": _try_parse_json(row_dict.get("headers", {})),
            "payload": _try_parse_json(row_dict.get("payload", {})),
            "query_params": _try_parse_json(row_dict.get("query_params", {})),
            "reason": reason,
            "predicted_class": row_dict.get("predicted_class") or "unknown",
            "confidence_score": confidence_display,
            "anomaly_score": anomaly_display,
            "anomaly_verdict": anomaly_verdict,
            "decision": decision,
            "features": features,
            # extras the UI doesn't render today but are handy for future use
            "label": row_dict.get("label"),
            "rule_label": row_dict.get("rule_label"),
            "rule_decision": row_dict.get("rule_decision"),
            "rule_risk_score": row_dict.get("rule_risk_score"),
            "fusion_risk_score": row_dict.get("fusion_risk_score"),
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading request details", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading request details", 500, e)
    finally:
        if conn:
            conn.close()


# ──────────────────────────────────────────────────────────────────────────
# POST /api/request-action/unblock-resend
# ──────────────────────────────────────────────────────────────────────────
RESEND_TIMEOUT = 30


@request_investigation_bp.route("/api/request-action/unblock-resend", methods=["POST"])
def unblock_and_resend():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        data = request.get_json(silent=True) or {}
        request_id = data.get("id")
        if not request_id:
            return json_error("Missing request id", 400)

        # 1. Pull the original request data we need to replay it
        cursor.execute("""
            SELECT method, path, headers, payload, query_params
            FROM api_logs
            WHERE id = ?
        """, (request_id,))
        row = cursor.fetchone()
        if not row:
            return json_error("Request not found", 404)

        original = dict(row)
        method = (original.get("method") or "GET").upper()
        path = original.get("path") or "/"
        headers = _try_parse_json(original.get("headers")) or {}
        query_params = _try_parse_json(original.get("query_params")) or {}
        payload = original.get("payload") or ""

        # Strip headers that shouldn't be replayed (hop-by-hop, host-specific)
        excluded_headers = {"host", "content-length", "connection", "authorization"}
        clean_headers = {
            k: v for k, v in headers.items()
            if isinstance(k, str) and k.lower() not in excluded_headers
        }

        # 2. Mark the row as safe FIRST so the UI is consistent even if resend fails
        cursor.execute("""
            UPDATE api_logs
            SET predicted_class = 'normal',
                anomaly_flag = 0,
                decision = 'allow',
                label = 'normal',
                reason = 'False positive — reviewed by analyst and resent'
            WHERE id = ?
        """, (request_id,))
        conn.commit()

        # 3. Actually send the request to the backend
        target_url = f"{BACKEND_BASE_URL.rstrip('/')}{path if path.startswith('/') else '/' + path}"

        try:
            resp = requests.request(
                method=method,
                url=target_url,
                headers=clean_headers,
                params=query_params if query_params else None,
                data=payload if payload else None,
                timeout=RESEND_TIMEOUT,
            )
            resend_status = resp.status_code
            resend_ok = 200 <= resp.status_code < 400
            resend_body_preview = (resp.text or "")[:500]
            resend_error = None

        except requests.RequestException as e:
            resend_status = None
            resend_ok = False
            resend_body_preview = None
            resend_error = str(e)

        return jsonify({
            "success": True,
            "message": (
                "Request marked safe and resent successfully"
                if resend_ok
                else "Request marked safe, but resend to backend failed"
            ),
            "marked_safe": True,
            "resend": {
                "ok": resend_ok,
                "status_code": resend_status,
                "target_url": target_url,
                "body_preview": resend_body_preview,
                "error": resend_error,
            },
        })

    except sqlite3.Error as e:
        return json_error("Database error while unblocking request", 500, e)
    except Exception as e:
        return json_error("Unexpected error while unblocking request", 500, e)
    finally:
        if conn:
            conn.close()


# ──────────────────────────────────────────────────────────────────────────
# POST /api/request-action/label   ← analyst override (Normal/Suspicious/Malicious)
# Stores the override directly in api_logs.label (which already exists).
# ──────────────────────────────────────────────────────────────────────────
@request_investigation_bp.route("/api/request-action/label", methods=["POST"])
def label_request():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        data = request.get_json(silent=True) or {}
        request_id = data.get("id")
        label = (data.get("label") or "").strip().lower()

        if not request_id:
            return json_error("Missing request id", 400)
        if label not in {"normal", "suspicious", "malicious"}:
            return json_error("Invalid label. Must be normal, suspicious, or malicious.", 400)

        cursor.execute("SELECT id FROM api_logs WHERE id = ?", (request_id,))
        if not cursor.fetchone():
            return json_error("Request not found", 404)

        # Derive anomaly_flag and decision from the analyst's label
        if label == "normal":
            anomaly_flag = 0
            decision = "allow"
        elif label == "suspicious":
            anomaly_flag = 1
            decision = "flag"
        else:  # malicious
            anomaly_flag = 1
            decision = "block"

        reason = f"Manually labeled '{label}' by analyst on {datetime.utcnow().isoformat(timespec='seconds')}Z"

        cursor.execute("""
            UPDATE api_logs
            SET predicted_class = ?,
                label = ?,
                decision = ?,
                anomaly_flag = ?,
                reason = ?
            WHERE id = ?
        """, (label, label, decision, anomaly_flag, reason, request_id))

        conn.commit()
        return jsonify({
            "success": True,
            "message": f"Label '{label}' saved successfully",
            "label": label,
            "decision": decision,
        })

    except sqlite3.Error as e:
        return json_error("Database error while saving label", 500, e)
    except Exception as e:
        return json_error("Unexpected error while saving label", 500, e)
    finally:
        if conn:
            conn.close()


# ──────────────────────────────────────────────────────────────────────────
# POST /api/retrain
# Triggers a model retrain using the analyst-provided labels in api_logs.label.
# Delegates to a `retrain_from_feedback(rows)` function in your ML module if
# present, and records the run in model_runs / model_current_metrics.
# ──────────────────────────────────────────────────────────────────────────
@request_investigation_bp.route("/api/retrain", methods=["POST"])
def retrain():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Pull all rows that have a human label
        cursor.execute("""
            SELECT *
            FROM api_logs
            WHERE label IS NOT NULL
              AND TRIM(label) != ''
        """)
        rows = [dict(r) for r in cursor.fetchall()]

        if len(rows) < 5:
            return jsonify({
                "success": False,
                "message": (
                    f"Not enough labeled samples to retrain "
                    f"({len(rows)} found — need at least 5). "
                    f"Use the Normal/Suspicious/Malicious buttons to label more requests first."
                )
            }), 400

        # Try to delegate to your real training pipeline.
        accuracy = precision = recall = f1 = roc_auc = threshold = None
        metrics_json = None
        model_name = "random_forest"

        try:
            # Adjust this import path if your module lives elsewhere
            from ml_model import retrain_from_feedback  # type: ignore
            result = retrain_from_feedback(rows) or {}

            if isinstance(result, dict):
                accuracy = result.get("accuracy")
                precision = result.get("precision")
                recall = result.get("recall")
                f1 = result.get("f1")
                roc_auc = result.get("roc_auc")
                threshold = result.get("threshold")
                model_name = result.get("model_name", model_name)
                metrics_json = json.dumps(result, default=str)
        except ImportError:
            return jsonify({
                "success": False,
                "message": (
                    "Retraining hook not configured. Add a "
                    "`retrain_from_feedback(rows)` function in `ml_model.py` "
                    "that returns a dict with at least an 'accuracy' key."
                )
            }), 501
        except Exception as e:
            return json_error("Retraining failed inside ML pipeline", 500, e)

        # Record the run
        trained_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        cursor.execute("""
            INSERT INTO model_runs
                (model_name, trained_at, accuracy, precision_score, recall, f1, roc_auc, threshold, metrics_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (model_name, trained_at, accuracy, precision, recall, f1, roc_auc, threshold, metrics_json))
        run_id = cursor.lastrowid

        # Upsert the "current" metrics row
        cursor.execute("""
            INSERT INTO model_current_metrics
                (model_name, last_trained_at, accuracy, precision_score, recall, f1, roc_auc, threshold, last_run_id, metrics_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(model_name) DO UPDATE SET
                last_trained_at = excluded.last_trained_at,
                accuracy = excluded.accuracy,
                precision_score = excluded.precision_score,
                recall = excluded.recall,
                f1 = excluded.f1,
                roc_auc = excluded.roc_auc,
                threshold = excluded.threshold,
                last_run_id = excluded.last_run_id,
                metrics_json = excluded.metrics_json
        """, (model_name, trained_at, accuracy, precision, recall, f1, roc_auc, threshold, run_id, metrics_json))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Model retrained successfully",
            "samples_used": len(rows),
            "run_id": run_id,
            "model_name": model_name,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "roc_auc": roc_auc,
            "threshold": threshold,
        })

    except sqlite3.Error as e:
        return json_error("Database error during retraining", 500, e)
    except Exception as e:
        return json_error("Unexpected error during retraining", 500, e)
    finally:
        if conn:
            conn.close()