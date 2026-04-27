import sqlite3
import json
from flask import Blueprint, jsonify, request
from database import get_connection
from utils import json_error

request_investigation_bp = Blueprint("request_investigation", __name__)

@request_investigation_bp.route("/api/request-details", methods=["GET"])
def request_details():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        request_id = request.args.get("id", "").strip()
        if not request_id:
            return json_error("Missing request id", 400)

        # Read actual columns from api_logs
        cursor.execute("PRAGMA table_info(api_logs)")
        columns_info = cursor.fetchall()
        available_columns = {row["name"] for row in columns_info}

        # Columns we want if they exist
        desired_columns = [
            "id",
            "timestamp",
            "ip_address",
            "method",
            "path",
            "headers",
            "body",
            "query_params",
            "predicted_class",
            "reason",
            "confidence_score",
            "anomaly_score",
            "anomaly_verdict",
            "decision",
            "response_time_ms"
        ]

        selected_columns = [col for col in desired_columns if col in available_columns]

        if not selected_columns:
            return json_error("api_logs table has no expected columns", 500)

        query = f"""
            SELECT {", ".join(selected_columns)}
            FROM api_logs
            WHERE id = ?
        """

        cursor.execute(query, (request_id,))
        row = cursor.fetchone()

        if not row:
            return json_error("Request not found", 404)

        import json

        def try_parse_json(value):
            if value is None or value == "":
                return {}
            if isinstance(value, (dict, list)):
                return value
            try:
                return json.loads(value)
            except Exception:
                return value

        row_dict = dict(row)

        predicted_class = (row_dict.get("predicted_class") or "").lower()

        # Safe defaults if columns do not exist
        reason = row_dict.get("reason") or "No reason available"
        anomaly_verdict = row_dict.get("anomaly_verdict") or predicted_class or "unknown"

        if "decision" in row_dict and row_dict.get("decision"):
            decision = row_dict["decision"]
        else:
            if predicted_class == "malicious":
                decision = "block"
            elif predicted_class == "suspicious":
                decision = "flag"
            else:
                decision = "allow"

        payload_value = row_dict.get("body", {})
        headers_value = row_dict.get("headers", {})
        query_params_value = row_dict.get("query_params", {})

        features = {
            "method": row_dict.get("method", "-"),
            "path_length": len(row_dict.get("path") or ""),
            "body_length": len(row_dict.get("body") or ""),
            "has_query_params": 1 if row_dict.get("query_params") else 0,
            "has_headers": 1 if row_dict.get("headers") else 0,
            "response_time_ms": row_dict.get("response_time_ms", 0) or 0
        }

        return jsonify({
            "success": True,
            "id": row_dict.get("id"),
            "timestamp": row_dict.get("timestamp", "-"),
            "ip_address": row_dict.get("ip_address", "-"),
            "method": row_dict.get("method", "-"),
            "path": row_dict.get("path", "-"),
            "headers": try_parse_json(headers_value),
            "payload": try_parse_json(payload_value),
            "query_params": try_parse_json(query_params_value),
            "reason": reason,
            "predicted_class": row_dict.get("predicted_class", "unknown"),
            "confidence_score": row_dict.get("confidence_score", "-"),
            "anomaly_score": row_dict.get("anomaly_score", "-"),
            "anomaly_verdict": anomaly_verdict,
            "decision": decision,
            "features": features
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading request details", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading request details", 500, e)
    finally:
        if conn:
            conn.close()

            
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

        cursor.execute("""
            SELECT
                id,
                predicted_class,
                decision,
                reason
            FROM api_logs
            WHERE id = ?
        """, (request_id,))
        row = cursor.fetchone()

        if not row:
            return json_error("Request not found", 404)

        cursor.execute("""
            UPDATE api_logs
            SET
                predicted_class = 'normal',
                anomaly_verdict = 'normal',
                decision = 'allow',
                reason = 'False positive reviewed by analyst and resent successfully'
            WHERE id = ?
        """, (request_id,))

        try:
            cursor.execute("DELETE FROM blocked_requests WHERE id = ?", (request_id,))
        except sqlite3.Error:
            pass

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Request unblocked and resent successfully"
        })

    except sqlite3.Error as e:
        return json_error("Database error while unblocking request", 500, e)
    except Exception as e:
        return json_error("Unexpected error while unblocking request", 500, e)
    finally:
        if conn:
            conn.close()

@request_investigation_bp.route("/api/request-action/mark-safe", methods=["POST"])
def mark_safe():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        data = request.get_json(silent=True) or {}
        request_id = data.get("id")

        if not request_id:
            return json_error("Missing request id", 400)

        cursor.execute("""
            SELECT id
            FROM api_logs
            WHERE id = ?
        """, (request_id,))
        row = cursor.fetchone()

        if not row:
            return json_error("Request not found", 404)

        cursor.execute("""
            UPDATE api_logs
            SET
                predicted_class = 'normal',
                anomaly_verdict = 'normal',
                decision = 'allow',
                reason = 'Reviewed manually and marked safe'
            WHERE id = ?
        """, (request_id,))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Request marked as safe"
        })

    except sqlite3.Error as e:
        return json_error("Database error while marking request safe", 500, e)
    except Exception as e:
        return json_error("Unexpected error while marking request safe", 500, e)
    finally:
        if conn:
            conn.close()
