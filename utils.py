from flask import jsonify


def json_error(message, status_code=500, details=None):
    return jsonify({
        "success": False,
        "error": message,
        "details": str(details) if details else None
    }), status_code


def safe_div(numerator, denominator):
    return round((numerator / denominator) * 100, 2) if denominator else 0.0


def get_table_columns(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return {row["name"] for row in cursor.fetchall()}