from flask import Flask, jsonify, render_template, request
import sqlite3
import os


app = Flask(__name__, template_folder="templates")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "sam_ads (1).db")


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def json_error(message, status_code=500, details=None):
    return jsonify({
        "success": False,
        "error": message,
        "details": str(details) if details else None
    }), status_code


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Route not found"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500


@app.route("/")
def home():
    return render_template("Home.html")

@app.route("/live-requests")
def live_requests_page():
    return render_template("LiveMetrics.html")

@app.route("/attack-analytics")
def attack_analytics_page():
    return render_template("AttackAnalytics.html")

@app.route("/request-investigation")
def request_investigation_page():
    return render_template("RequestInvestigation.html")

@app.route("/model-performance")
def model_performance_page():
    return render_template("ModelPerformance.html")

@app.route("/url-scanner")
def url_scanner_page():
    return render_template("URLScanner.html")
@app.route("/email-alerts")
def email_alerts_page():
    return render_template("EmailAlerts.html")
@app.route("/api/dashboard/summary", methods=["GET"])
def dashboard_summary():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) AS total FROM api_logs")
        total_requests = cursor.fetchone()["total"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM api_logs
            WHERE predicted_class = 'normal'
        """)
        normal_count = cursor.fetchone()["count"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM api_logs
            WHERE predicted_class = 'suspicious'
        """)
        suspicious_count = cursor.fetchone()["count"] or 0

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM api_logs
            WHERE predicted_class = 'malicious'
        """)
        malicious_count = cursor.fetchone()["count"] or 0

        blocked_count = 0
        try:
            cursor.execute("SELECT COUNT(*) AS count FROM blocked_requests")
            blocked_count = cursor.fetchone()["count"] or 0
        except sqlite3.Error:
            blocked_count = 0

        normal_percentage = round((normal_count / total_requests) * 100, 2) if total_requests else 0
        detection_rate = round(((suspicious_count + malicious_count) / total_requests) * 100, 2) if total_requests else 0

        return jsonify({
            "success": True,
            "total_requests": total_requests,
            "normal_percentage": normal_percentage,
            "suspicious_requests": suspicious_count,
            "malicious_requests": malicious_count,
            "blocked_requests": blocked_count,
            "detection_rate": detection_rate
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading dashboard summary", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading dashboard summary", 500, e)
    finally:
        if conn:
            conn.close()


@app.route("/api/dashboard/class-distribution", methods=["GET"])
def class_distribution():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT LOWER(TRIM(predicted_class)) AS predicted_class, COUNT(*) AS count
            FROM api_logs
            WHERE predicted_class IS NOT NULL
            GROUP BY LOWER(TRIM(predicted_class))
        """)
        rows = cursor.fetchall()

        result = {
            "success": True,
            "Normal": 0,
            "Suspicious": 0,
            "Malicious": 0
        }

        for row in rows:
            label = row["predicted_class"]

            if label == "normal":
                result["Normal"] = row["count"]
            elif label == "suspicious":
                result["Suspicious"] = row["count"]
            elif label == "malicious":
                result["Malicious"] = row["count"]

        return jsonify(result)

    except sqlite3.Error as e:
        return json_error("Database error while loading class distribution", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading class distribution", 500, e)
    finally:
        if conn:
            conn.close()

@app.route("/api/dashboard/recent-requests", methods=["GET"])
def recent_requests():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

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
                "status": row["predicted_class"] if row["predicted_class"] else "Unknown",
                "response_time_ms": row["response_time_ms"] if row["response_time_ms"] is not None else 0,
                "timestamp": row["timestamp"]
            })

        return jsonify({
            "success": True,
            "data": data
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading recent requests", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading recent requests", 500, e)
    finally:
        if conn:
            conn.close()


@app.route("/api/dashboard/traffic-trend", methods=["GET"])
def traffic_trend():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                strftime('%H:%M', timestamp) AS time_slot,
                SUM(CASE WHEN predicted_class = 'normal' THEN 1 ELSE 0 END) AS normal_count,
                SUM(CASE WHEN predicted_class = 'malicious' THEN 1 ELSE 0 END) AS malicious_count,
                SUM(CASE WHEN predicted_class = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count
            FROM api_logs
            GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
            ORDER BY MIN(datetime(timestamp)) ASC
            LIMIT 10
        """)
        rows = cursor.fetchall()

        labels = []
        normal_data = []
        malicious_data = []
        suspicious_data = []

        for row in rows:
            labels.append(row["time_slot"])
            normal_data.append(row["normal_count"] or 0)
            malicious_data.append(row["malicious_count"] or 0)
            suspicious_data.append(row["suspicious_count"] or 0)

        return jsonify({
            "success": True,
            "labels": labels,
            "normal": normal_data,
            "malicious": malicious_data,
            "suspicious": suspicious_data
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading traffic trend", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading traffic trend", 500, e)
    finally:
        if conn:
            conn.close()
@app.route("/api/live-requests", methods=["GET"])
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
                "decision": row["decision"] if "decision" in row.keys() else "Allowed",
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
@app.route("/api/attack-analytics/attack-types", methods=["GET"])
def attack_types():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                COALESCE(NULLIF(TRIM(reason), ''), 'Unknown') AS reason,
                COUNT(*) AS count
            FROM api_logs
            WHERE LOWER(TRIM(predicted_class)) IN ('malicious', 'suspicious')
            GROUP BY COALESCE(NULLIF(TRIM(reason), ''), 'Unknown')
            ORDER BY count DESC
            LIMIT 10
        """)
        rows = cursor.fetchall()

        return jsonify({
            "success": True,
            "labels": [row["reason"] for row in rows],
            "values": [row["count"] for row in rows]
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading attack types", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading attack types", 500, e)
    finally:
        if conn:
            conn.close()

@app.route("/api/attack-analytics/top-ips", methods=["GET"])
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

@app.route("/api/attack-analytics/top-endpoints", methods=["GET"])
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

@app.route("/api/attack-analytics/blocked-trends", methods=["GET"])
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


@app.route("/api/request-details", methods=["GET"])
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

            
@app.route("/api/request-action/unblock-resend", methods=["POST"])
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
            conn.close()@app.route("/api/request-action/mark-safe", methods=["POST"])
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

import re
from urllib.parse import urlparse, parse_qs

@app.route("/api/scan-url", methods=["POST"])
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

@app.route("/api/label", methods=["POST"])
def label_request():
    conn = None
    try:
        data = request.get_json()  # ✅ safer than request.json

        request_id = data.get("id")
        label = data.get("label")

        if not request_id or not label:
            return jsonify({
                "success": False,
                "error": "Missing id or label"
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE api_logs
            SET label = ?
            WHERE id = ?
        """, (label.lower(), request_id))  # ✅ normalize label

        conn.commit()

        return jsonify({"success": True})

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Error labeling request",
            "details": str(e)
        }), 500

    finally:
        if conn:
            conn.close()


@app.route("/api/retrain", methods=["POST"])
def retrain():
    conn = None
    try:
        conn = get_connection()

        df = pd.read_sql_query("""
            SELECT * FROM api_logs
            WHERE label IS NOT NULL
        """, conn)

        # ✅ safety check
        if df.empty or len(df) < 50:
            return jsonify({
                "success": False,
                "message": "Not enough labeled data (need at least 50)"
            })

        # ✅ ensure columns exist
        for col in ["payload", "path"]:
            if col not in df.columns:
                df[col] = ""

        df["payload"] = df["payload"].fillna("")
        df["path"] = df["path"].fillna("")

        # ✅ features
        df["payload_length"] = df["payload"].astype(str).str.len()
        df["url_length"] = df["path"].astype(str).str.len()

        df["has_sql"] = df["payload"].str.contains(
            r"select|drop|union|insert|update|delete",
            case=False, na=False
        ).astype(int)

        df["has_xss"] = df["payload"].str.contains(
            r"<script>|onerror=|alert\(",
            case=False, na=False
        ).astype(int)

        # ✅ features + labels
        X = df[["payload_length", "url_length", "has_sql", "has_xss"]]
        y = df["label"].str.lower()  # normalize

        # ✅ train model
        model = RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )

        model.fit(X, y)

        # ✅ SAVE MODEL (VERY IMPORTANT PATH)
        model_path = os.path.join(BASE_DIR, "rf_model_updated.pkl")
        joblib.dump(model, model_path)

        return jsonify({
            "success": True,
            "message": f"Model retrained successfully ({len(df)} samples)"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Retraining failed",
            "details": str(e)
        }), 500

    finally:
        if conn:
            conn.close()
@app.route("/api/dashboard/alerts", methods=["GET"])
def get_alerts():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM alerts
        ORDER BY datetime(timestamp) DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()

    data = [dict(row) for row in rows]

    return jsonify({
        "success": True,
        "data": data
    })

if __name__ == "__main__":
    print(f"Using database: {DB_NAME}")
    app.run(debug=True, port=5000)