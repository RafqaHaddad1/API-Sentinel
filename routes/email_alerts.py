import sqlite3
import re
from flask import Blueprint, jsonify, request
from database import get_connection
from utils import json_error, get_table_columns

email_alerts_bp = Blueprint("email_alerts", __name__)

@email_alerts_bp.route("/api/email-alerts/config", methods=["GET"])
def get_email_alert_config():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT config_id, recipient_email
            FROM email_alert_config
            ORDER BY config_id DESC
        """)

        recipients = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            "success": True,
            "recipients": recipients
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading recipients", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading recipients", 500, e)
    finally:
        if conn:
            conn.close()


@email_alerts_bp.route("/api/email-alerts/config", methods=["POST"])
def add_email_alert_recipient():
    conn = None
    try:
        data = request.get_json(silent=True) or {}
        recipient_email = (data.get("recipient_email") or "").strip().lower()

        if not recipient_email:
            return json_error("Recipient email is required", 400)

        if not is_valid_email(recipient_email):
            return json_error("Invalid email address", 400)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO email_alert_config (
                recipient_email,
                is_active,
                created_at,
                updated_at
            )
            VALUES (?, 1, datetime('now'), datetime('now'))
        """, (recipient_email,))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Recipient added successfully",
            "recipient": {
                "config_id": cursor.lastrowid,
                "recipient_email": recipient_email,
                "is_active": 1
            }
        })

    except sqlite3.IntegrityError:
        return json_error("This email already exists", 400)
    except sqlite3.Error as e:
        return json_error("Database error while adding recipient", 500, e)
    except Exception as e:
        return json_error("Unexpected error while adding recipient", 500, e)
    finally:
        if conn:
            conn.close()


@email_alerts_bp.route("/api/email-alerts/config/<int:recipient_id>", methods=["PUT"])
def update_email_alert_recipient(recipient_id):
    conn = None
    try:
        data = request.get_json(silent=True) or {}
        recipient_email = (data.get("recipient_email") or "").strip().lower()

        if not recipient_email:
            return json_error("Recipient email is required", 400)

        if not is_valid_email(recipient_email):
            return json_error("Invalid email address", 400)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE email_alert_config
            SET recipient_email = ?,
                updated_at = datetime('now')
            WHERE config_id = ?
        """, (recipient_email, recipient_id))

        conn.commit()

        if cursor.rowcount == 0:
            return json_error("Recipient not found", 404)

        return jsonify({
            "success": True,
            "message": "Recipient updated successfully",
            "recipient": {
                "id": recipient_id,
                "recipient_email": recipient_email
            }
        })

    except sqlite3.IntegrityError:
        return json_error("This email already exists", 400)
    except sqlite3.Error as e:
        return json_error("Database error while updating recipient", 500, e)
    except Exception as e:
        return json_error("Unexpected error while updating recipient", 500, e)
    finally:
        if conn:
            conn.close()

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def is_valid_email(email):
    return bool(EMAIL_RE.match(email or ""))

@email_alerts_bp.route("/api/email-alerts/config/<int:recipient_id>", methods=["DELETE"])
def delete_email_alert_recipient(recipient_id):
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM email_alert_config
            WHERE config_id = ?
        """, (recipient_id,))

        conn.commit()

        if cursor.rowcount == 0:
            return json_error("Recipient not found", 404)

        return jsonify({
            "success": True,
            "message": "Recipient deleted successfully"
        })

    except sqlite3.Error as e:
        return json_error("Database error while deleting recipient", 500, e)
    except Exception as e:
        return json_error("Unexpected error while deleting recipient", 500, e)
    finally:
        if conn:
            conn.close()


@email_alerts_bp.route("/api/email-alerts/config/<int:recipient_id>/toggle", methods=["PATCH"])
def toggle_email_alert_recipient(recipient_id):
    conn = None
    try:
        data = request.get_json(silent=True) or {}
        is_active = data.get("is_active")

        if is_active is None:
            return json_error("is_active is required", 400)

        is_active = 1 if bool(is_active) else 0

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE email_alert_config
            SET is_active = ?,
                updated_at = datetime('now')
            WHERE config_id = ?
        """, (is_active, recipient_id))

        conn.commit()

        if cursor.rowcount == 0:
            return json_error("Recipient not found", 404)

        return jsonify({
            "success": True,
            "message": "Recipient status updated successfully",
            "id": recipient_id,
            "is_active": is_active
        })

    except sqlite3.Error as e:
        return json_error("Database error while updating recipient status", 500, e)
    except Exception as e:
        return json_error("Unexpected error while updating recipient status", 500, e)
    finally:
        if conn:
            conn.close()

@email_alerts_bp.route("/api/email-alerts/metrics", methods=["GET"])
def email_alert_metrics():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Prefer dedicated email history table
        history_tables = get_table_columns(cursor, "email_alert_history")
        if history_tables:
            cursor.execute("""
                SELECT
                    COUNT(*) AS total_sent,
                    SUM(CASE WHEN LOWER(COALESCE(severity, '')) = 'malicious' THEN 1 ELSE 0 END) AS malicious_alerts,
                    SUM(CASE WHEN LOWER(COALESCE(severity, '')) = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_alerts,
                    SUM(CASE WHEN LOWER(COALESCE(delivery_status, '')) = 'success' THEN 1 ELSE 0 END) AS sent_count,
                    SUM(CASE WHEN LOWER(COALESCE(delivery_status, '')) = 'failed' THEN 1 ELSE 0 END) AS failed_count
                FROM email_alert_history
            """)
            row = cursor.fetchone()

            total_sent = row["total_sent"] or 0
            sent_count = row["sent_count"] or 0
            delivery_rate = round((sent_count / total_sent) * 100, 2) if total_sent else 0

            return jsonify({
                "success": True,
                "total_sent": total_sent,
                "malicious_alerts": row["malicious_alerts"] or 0,
                "suspicious_alerts": row["suspicious_alerts"] or 0,
                "delivery_rate": delivery_rate
            })

        return jsonify({
            "success": True,
            "total_sent": 0,
            "malicious_alerts": 0,
            "suspicious_alerts": 0,
            "delivery_rate": 0
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading email alert metrics", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading email alert metrics", 500, e)
    finally:
        if conn:
            conn.close()

@email_alerts_bp.route("/api/email-alerts/history", methods=["GET"])
def email_alert_history():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                timestamp,
                recipient,
                severity,
                trigger,
                ip_address,
                endpoint,
                delivery_status,
                error_message,
                email_html,
                threat_score
            FROM email_alert_history
        """)

        rows = cursor.fetchall()

        data = []
        for row in rows:
            data.append({
                "timestamp": row["timestamp"],
                "recipient": row["recipient"],
                "severity": row["severity"],
                "trigger": row["trigger"],
                "ip_address": row["ip_address"],
                "endpoint": row["endpoint"],
                "delivery_status": row["delivery_status"],
                "error_message": row["error_message"],
                "email_html": row["email_html"],
                "threat_score": row["threat_score"]
            })

        return jsonify({
            "success": True,
            "data": data
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading email alert history", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading email alert history", 500, e)
    finally:
        if conn:
            conn.close()
