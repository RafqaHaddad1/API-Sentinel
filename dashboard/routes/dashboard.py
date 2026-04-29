from flask import Blueprint, jsonify, request
import sqlite3
from database import get_connection
from utils import json_error

dashboard_bp = Blueprint("dashboard", __name__)

def get_selected_date():
    return request.args.get("date", "").strip()

@dashboard_bp.route("/api/dashboard/summary", methods=["GET"])
def dashboard_summary():
    conn = None
    try:
        selected_date = get_selected_date()

        conn = get_connection()
        cursor = conn.cursor()

        date_filter = ""
        params = []

        if selected_date:
            date_filter = "WHERE date(timestamp) = date(?)"
            params.append(selected_date)

        cursor.execute(f"""
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN LOWER(predicted_class) = 'normal' THEN 1 ELSE 0 END), 0) AS normal_count,
                COALESCE(SUM(CASE WHEN LOWER(predicted_class) = 'suspicious' THEN 1 ELSE 0 END), 0) AS suspicious_count,
                COALESCE(SUM(CASE WHEN LOWER(predicted_class) = 'malicious' THEN 1 ELSE 0 END), 0) AS malicious_count
            FROM api_logs
            {date_filter}
        """, params)

        row = cursor.fetchone()

        total_requests = row["total"] or 0
        normal_count = row["normal_count"] or 0
        suspicious_count = row["suspicious_count"] or 0
        malicious_count = row["malicious_count"] or 0

        detection_rate = round(((suspicious_count + malicious_count) / total_requests) * 100, 2) if total_requests else 0
        normal_percentage = round((normal_count / total_requests) * 100, 2) if total_requests else 0

        return jsonify({
            "success": True,
            "selected_date": selected_date,
            "total_requests": total_requests,
            "normal_percentage": normal_percentage,
            "suspicious_requests": suspicious_count,
            "malicious_requests": malicious_count,
            "detection_rate": detection_rate
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading dashboard summary", 500, e)
    finally:
        if conn:
            conn.close()

@dashboard_bp.route("/api/dashboard/class-distribution", methods=["GET"])
def class_distribution():
    conn = None
    try:
        selected_date = get_selected_date()

        conn = get_connection()
        cursor = conn.cursor()

        if selected_date:
            cursor.execute("""
                SELECT LOWER(TRIM(predicted_class)) AS predicted_class, COUNT(*) AS count
                FROM api_logs
                WHERE predicted_class IS NOT NULL
                  AND date(timestamp) = date(?)
                GROUP BY LOWER(TRIM(predicted_class))
            """, (selected_date,))
        else:
            cursor.execute("""
                SELECT LOWER(TRIM(predicted_class)) AS predicted_class, COUNT(*) AS count
                FROM api_logs
                WHERE predicted_class IS NOT NULL
                GROUP BY LOWER(TRIM(predicted_class))
            """)

        rows = cursor.fetchall()
        if not rows:
            return jsonify({
                "success": True,
                "Normal": 0,
                "Suspicious": 0,
                "Malicious": 0
            })
        result = {
            "success": True,
            "Normal": 0,
            "Suspicious": 0,
            "Malicious": 0
        }

        for row in rows:
            if row["predicted_class"] == "normal":
                result["Normal"] = row["count"]
            elif row["predicted_class"] == "suspicious":
                result["Suspicious"] = row["count"]
            elif row["predicted_class"] == "malicious":
                result["Malicious"] = row["count"]

        return jsonify(result)

    except sqlite3.Error as e:
        return json_error("Database error while loading class distribution", 500, e)
    finally:
        if conn:
            conn.close()

@dashboard_bp.route("/api/dashboard/recent-requests", methods=["GET"])
def recent_requests():
    conn = None
    try:
        selected_date = get_selected_date()

        conn = get_connection()
        cursor = conn.cursor()

        if selected_date:
            cursor.execute("""
                SELECT ip_address, path, method, predicted_class, response_time_ms, timestamp
                FROM api_logs
                WHERE date(timestamp) = date(?)
                ORDER BY datetime(timestamp) DESC
            """, (selected_date,))
        else:
            cursor.execute("""
                SELECT ip_address, path, method, predicted_class, response_time_ms, timestamp
                FROM api_logs
                ORDER BY datetime(timestamp) DESC
                LIMIT 10
            """)

        rows = cursor.fetchall()

        data = []
        for row in rows:
            data.append({
                "ip_address": row["ip_address"],
                "endpoint": row["path"],
                "method": row["method"],
                "status": row["predicted_class"] or "Unknown",
                "response_time_ms": row["response_time_ms"] or 0,
                "timestamp": row["timestamp"]
            })

        return jsonify({"success": True, "data": data})

    except sqlite3.Error as e:
        return json_error("Database error while loading recent requests", 500, e)
    finally:
        if conn:
            conn.close()

@dashboard_bp.route("/api/dashboard/traffic-trend", methods=["GET"])
def traffic_trend():
    conn = None
    try:
        selected_date = get_selected_date()

        conn = get_connection()
        cursor = conn.cursor()

        if selected_date:
            cursor.execute("""
                    SELECT
                        strftime('%H:%M', timestamp) AS time_slot,
                        SUM(CASE WHEN LOWER(predicted_class) = 'normal' THEN 1 ELSE 0 END) AS normal_count,
                        SUM(CASE WHEN LOWER(predicted_class) = 'malicious' THEN 1 ELSE 0 END) AS malicious_count,
                        SUM(CASE WHEN LOWER(predicted_class) = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count
                    FROM api_logs
                    WHERE date(timestamp) = date(?)
                    GROUP BY strftime('%H:%M', timestamp)
                    ORDER BY time_slot ASC
                """, (selected_date,))
        else:
            cursor.execute("""
                SELECT
                    date(timestamp) AS time_slot,
                    SUM(CASE WHEN LOWER(predicted_class) = 'normal' THEN 1 ELSE 0 END) AS normal_count,
                    SUM(CASE WHEN LOWER(predicted_class) = 'malicious' THEN 1 ELSE 0 END) AS malicious_count,
                    SUM(CASE WHEN LOWER(predicted_class) = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count
                FROM api_logs
                GROUP BY date(timestamp)
                ORDER BY date(timestamp) ASC
                LIMIT 7
            """)

        rows = cursor.fetchall()

        return jsonify({
            "success": True,
            "labels": [row["time_slot"] for row in rows],
            "normal": [row["normal_count"] or 0 for row in rows],
            "malicious": [row["malicious_count"] or 0 for row in rows],
            "suspicious": [row["suspicious_count"] or 0 for row in rows]
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading traffic trend", 500, e)
    finally:
        if conn:
            conn.close()