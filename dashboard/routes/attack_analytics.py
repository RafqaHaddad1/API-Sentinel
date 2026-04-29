import sqlite3
from flask import Blueprint, jsonify
from database import get_connection
from utils import json_error

attack_analytics_bp = Blueprint("attack_analytics", __name__)


@attack_analytics_bp.route("/api/attack-analytics/attack-types", methods=["GET"])
def attack_types():
    """Group blocked/flagged requests into clean attack categories
    instead of showing raw reason strings."""
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT reason, extracted_features
            FROM api_logs
            WHERE LOWER(TRIM(predicted_class)) IN ('malicious', 'suspicious')
        """)
        rows = cursor.fetchall()

        counts = {
            "SQL Injection":          0,
            "XSS":                    0,
            "Command Injection":      0,
            "Path Traversal":         0,
            "Malicious User-Agent":   0,
            "Anomaly Only":           0,
            "Other":                  0,
        }

        for row in rows:
            reason = (row["reason"] or "").lower()
            feats = {}
            try:
                raw = row["extracted_features"]
                if raw:
                    feats = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except Exception:
                feats = {}

            # Categorize using features first (most reliable), then reason text
            if feats.get("sql_pattern_hits", 0) > 0 or "sqli" in reason or "sql injection" in reason:
                counts["SQL Injection"] += 1
            elif feats.get("xss_pattern_hits", 0) > 0 or "xss" in reason:
                counts["XSS"] += 1
            elif feats.get("cmd_pattern_hits", 0) > 0 or "command injection" in reason:
                counts["Command Injection"] += 1
            elif feats.get("traversal_pattern_hits", 0) > 0 or "path traversal" in reason:
                counts["Path Traversal"] += 1
            elif feats.get("bad_ua_pattern_hits", 0) > 0 or "user agent" in reason or "scanner" in reason:
                counts["Malicious User-Agent"] += 1
            elif "anomaly" in reason or "isolation" in reason:
                counts["Anomaly Only"] += 1
            else:
                counts["Other"] += 1

        # Drop empty categories so the chart only shows what's relevant
        filtered = {k: v for k, v in counts.items() if v > 0}

        # Sort descending so the biggest category appears first
        sorted_items = sorted(filtered.items(), key=lambda x: x[1], reverse=True)

        return jsonify({
            "success": True,
            "labels": [k for k, _ in sorted_items],
            "values": [v for _, v in sorted_items],
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading attack types", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading attack types", 500, e)
    finally:
        if conn:
            conn.close()

@attack_analytics_bp.route("/api/attack-analytics/top-ips", methods=["GET"])
def top_ips():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                ip_address,
                COUNT(*) AS count
            FROM api_logs
            WHERE LOWER(TRIM(predicted_class)) = 'malicious'
            GROUP BY ip_address
            ORDER BY count DESC
            LIMIT 10
        """)
        rows = cursor.fetchall()

        return jsonify({
            "success": True,
            "labels": [row["ip_address"] for row in rows],
            "values": [row["count"] for row in rows]
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading top malicious IPs", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading top malicious IPs", 500, e)
    finally:
        if conn:
            conn.close()

@attack_analytics_bp.route("/api/attack-analytics/top-endpoints", methods=["GET"])
def top_endpoints():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                path,
                COUNT(*) AS count
            FROM api_logs
            WHERE LOWER(TRIM(predicted_class)) IN ('malicious', 'suspicious')
            GROUP BY path
            ORDER BY count DESC
            LIMIT 10
        """)
        rows = cursor.fetchall()

        return jsonify({
            "success": True,
            "labels": [row["path"] for row in rows],
            "values": [row["count"] for row in rows]
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading attacked endpoints", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading attacked endpoints", 500, e)
    finally:
        if conn:
            conn.close()

@attack_analytics_bp.route("/api/attack-analytics/blocked-trends", methods=["GET"])
def blocked_trends():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                strftime('%H:%M', timestamp) AS time_slot,
                COUNT(*) AS count
            FROM api_logs
            WHERE LOWER(TRIM(predicted_class)) = 'malicious'
            GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
            ORDER BY MIN(datetime(timestamp)) ASC
            LIMIT 10
        """)
        rows = cursor.fetchall()

        return jsonify({
            "success": True,
            "labels": [row["time_slot"] for row in rows],
            "values": [row["count"] for row in rows]
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading blocked trends", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading blocked trends", 500, e)
    finally:
        if conn:
            conn.close()
