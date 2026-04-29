import sqlite3
from flask import Blueprint, jsonify, request
from database import get_connection
from utils import json_error

live_requests_bp = Blueprint("live_requests", __name__)

@live_requests_bp.route("/api/live-requests", methods=["GET"])
def live_requests():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        ip = request.args.get("ip", "").strip()
        endpoint = request.args.get("endpoint", "").strip()
        method = request.args.get("method", "").strip()
        status = request.args.get("status", "").strip()
        from_date = request.args.get("from", "").strip()

        query = """
            SELECT
                id,
                timestamp,
                ip_address,
                path,
                method,
                predicted_class,
                decision,
                response_time_ms
            FROM api_logs
            WHERE 1=1
        """
        params = []

        if ip:
            query += " AND ip_address LIKE ?"
            params.append(f"%{ip}%")

        if endpoint:
            query += " AND path LIKE ?"
            params.append(f"%{endpoint}%")

        if method:
            query += " AND UPPER(method) = UPPER(?)"
            params.append(method)

        if status:
            if status.lower() == "blocked":
                query += " AND LOWER(decision) IN ('blocked', 'block')"
            else:
                query += " AND LOWER(predicted_class) = LOWER(?)"
                params.append(status)

        if from_date:
            query += " AND datetime(timestamp) >= datetime(?)"
            params.append(from_date)

        query += " ORDER BY datetime(timestamp) DESC LIMIT 100"

        cursor.execute(query, params)
        rows = cursor.fetchall()

        data = []
        for row in rows:
            data.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "ip_address": row["ip_address"],
                "path": row["path"],
                "method": row["method"],
                "predicted_class": row["predicted_class"],
                "response_time_ms": row["response_time_ms"] if row["response_time_ms"] is not None else 0
            })

        return jsonify({
            "success": True,
            "data": data
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading live requests", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading live requests", 500, e)
    finally:
        if conn:
            conn.close()