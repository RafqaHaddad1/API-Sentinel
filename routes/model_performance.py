
import sqlite3
from flask import Blueprint, jsonify
from database import get_connection
from utils import json_error, safe_div

model_performance_bp = Blueprint("model_performance", __name__)

def safe_div(numerator, denominator):
    return round((numerator / denominator) * 100, 2) if denominator else 0.0

@model_performance_bp.route("/api/model-performance/supervised", methods=["GET"])
def supervised_model_performance():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                LOWER(TRIM(COALESCE(label, ''))) AS true_label,
                LOWER(TRIM(COALESCE(predicted_class, ''))) AS predicted_label
            FROM api_logs
            WHERE label IS NOT NULL
              AND TRIM(label) <> ''
              AND predicted_class IS NOT NULL
              AND TRIM(predicted_class) <> ''
        """)
        rows = cursor.fetchall()

        tp = fp = tn = fn = 0

        for row in rows:
            true_attack = row["true_label"] in ("suspicious", "malicious")
            pred_attack = row["predicted_label"] in ("suspicious", "malicious")

            if true_attack and pred_attack:
                tp += 1
            elif not true_attack and pred_attack:
                fp += 1
            elif not true_attack and not pred_attack:
                tn += 1
            elif true_attack and not pred_attack:
                fn += 1

        total = tp + fp + tn + fn

        accuracy = safe_div(tp + tn, total)
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)

        f1 = 0.0
        if (precision + recall) > 0:
            f1 = round((2 * precision * recall) / (precision + recall), 2)

        return jsonify({
            "success": True,
            "metrics": {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1
            },
            "confusion_matrix": {
                "true_positive": tp,
                "false_positive": fp,
                "true_negative": tn,
                "false_negative": fn
            },
            "sample_count": total
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading supervised model performance", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading supervised model performance", 500, e)
    finally:
        if conn:
            conn.close()

@model_performance_bp.route("/api/model-performance/unsupervised", methods=["GET"])
def unsupervised_model_performance():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                COUNT(*) AS total_rows,
                AVG(COALESCE(iso_score, 0)) AS avg_iso_score,
                SUM(CASE WHEN COALESCE(anomaly_flag, 0) = 1 THEN 1 ELSE 0 END) AS anomalies_flagged,
                SUM(CASE WHEN COALESCE(iso_score, 0) >= 0.80 THEN 1 ELSE 0 END) AS high_risk_outliers,
                SUM(CASE WHEN COALESCE(anomaly_flag, 0) = 0 THEN 1 ELSE 0 END) AS normal_fit_count
            FROM api_logs
        """)
        row = cursor.fetchone()

        total_rows = row["total_rows"] or 0
        avg_iso_score = round(float(row["avg_iso_score"] or 0), 4)
        anomalies_flagged = row["anomalies_flagged"] or 0
        high_risk_outliers = row["high_risk_outliers"] or 0
        normal_pattern_fit = safe_div(row["normal_fit_count"] or 0, total_rows)

        cursor.execute("""
            SELECT
                substr(timestamp, 1, 16) AS time_slot,
                AVG(COALESCE(iso_score, 0)) AS avg_score
            FROM api_logs
            WHERE iso_score IS NOT NULL
            GROUP BY substr(timestamp, 1, 16)
            ORDER BY time_slot ASC
            LIMIT 12
        """)
        trend_rows = cursor.fetchall()

        labels = []
        anomaly_scores = []
        normal_scores = []

        for r in trend_rows:
            labels.append(r["time_slot"])
            score = float(r["avg_score"] or 0)
            anomaly_scores.append(round(score, 4))
            normal_scores.append(round(max(0.0, 1.0 - score), 4))

        return jsonify({
            "success": True,
            "metrics": {
                "avg_anomaly_score": avg_iso_score,
                "normal_pattern_fit": normal_pattern_fit,
                "anomalies_flagged": anomalies_flagged,
                "high_risk_outliers": high_risk_outliers
            },
            "trend": {
                "labels": labels,
                "normal_scores": normal_scores,
                "anomaly_scores": anomaly_scores
            }
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading unsupervised model performance", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading unsupervised model performance", 500, e)
    finally:
        if conn:
            conn.close()

@model_performance_bp.route("/api/model-performance/mitm", methods=["GET"])
def mitm_model_performance():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                COUNT(*) AS total_rows,
                SUM(CASE WHEN LOWER(TRIM(COALESCE(mitm_class, 'normal'))) IN ('suspicious', 'malicious') THEN 1 ELSE 0 END) AS mitm_alerts,
                SUM(CASE WHEN COALESCE(replay_flag, 0) = 1 THEN 1 ELSE 0 END) AS replay_events,
                SUM(CASE WHEN COALESCE(ip_changed, 0) = 1 THEN 1 ELSE 0 END) AS ip_changes,
                SUM(CASE WHEN COALESCE(user_agent_changed, 0) = 1 THEN 1 ELSE 0 END) AS user_agent_changes,
                SUM(CASE WHEN COALESCE(sequence_anomaly, 0) = 1 THEN 1 ELSE 0 END) AS sequence_anomalies,
                SUM(CASE WHEN COALESCE(hijack_score, 0) >= 60 THEN 1 ELSE 0 END) AS high_hijack_events
            FROM api_logs
        """)
        row = cursor.fetchone()

        cursor.execute("""
            SELECT
                substr(timestamp, 1, 16) AS time_slot,
                SUM(CASE WHEN COALESCE(replay_flag, 0) = 1 THEN 1 ELSE 0 END) AS replay_events,
                SUM(CASE WHEN COALESCE(ip_changed, 0) = 1 THEN 1 ELSE 0 END) AS ip_changes,
                SUM(CASE WHEN COALESCE(user_agent_changed, 0) = 1 THEN 1 ELSE 0 END) AS user_agent_changes,
                SUM(CASE WHEN COALESCE(sequence_anomaly, 0) = 1 THEN 1 ELSE 0 END) AS sequence_anomalies
            FROM api_logs
            GROUP BY substr(timestamp, 1, 16)
            ORDER BY time_slot ASC
            LIMIT 12
        """)
        trend_rows = cursor.fetchall()

        labels = []
        replay_data = []
        ip_change_data = []
        ua_change_data = []
        sequence_data = []

        for r in trend_rows:
            labels.append(r["time_slot"])
            replay_data.append(r["replay_events"] or 0)
            ip_change_data.append(r["ip_changes"] or 0)
            ua_change_data.append(r["user_agent_changes"] or 0)
            sequence_data.append(r["sequence_anomalies"] or 0)

        return jsonify({
            "success": True,
            "metrics": {
                "mitm_alerts": row["mitm_alerts"] or 0,
                "replay_events": row["replay_events"] or 0,
                "ip_changes": row["ip_changes"] or 0,
                "user_agent_changes": row["user_agent_changes"] or 0,
                "sequence_anomalies": row["sequence_anomalies"] or 0,
                "high_hijack_events": row["high_hijack_events"] or 0
            },
            "trend": {
                "labels": labels,
                "replay_events": replay_data,
                "ip_changes": ip_change_data,
                "user_agent_changes": ua_change_data,
                "sequence_anomalies": sequence_data
            }
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading MiTM model performance", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading MiTM model performance", 500, e)
    finally:
        if conn:
            conn.close()
def get_api_logs_columns(cursor):
    cursor.execute("PRAGMA table_info(api_logs)")
    return {row["name"] for row in cursor.fetchall()}

@model_performance_bp.route("/api/model-performance/all", methods=["GET"])
def all_model_performance():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        available_columns = get_api_logs_columns(cursor)

        has_iso_score = "iso_score" in available_columns
        has_anomaly_flag = "anomaly_flag" in available_columns
        has_mitm_class = "mitm_class" in available_columns
        has_replay_flag = "replay_flag" in available_columns
        has_ip_changed = "ip_changed" in available_columns
        has_user_agent_changed = "user_agent_changed" in available_columns
        has_sequence_anomaly = "sequence_anomaly" in available_columns
        has_hijack_score = "hijack_score" in available_columns

        # -----------------------------
        # Supervised
        # -----------------------------
        cursor.execute("""
            SELECT
                LOWER(TRIM(COALESCE(label, ''))) AS true_label,
                LOWER(TRIM(COALESCE(predicted_class, ''))) AS predicted_label
            FROM api_logs
            WHERE label IS NOT NULL
              AND TRIM(label) <> ''
              AND predicted_class IS NOT NULL
              AND TRIM(predicted_class) <> ''
        """)
        rows = cursor.fetchall()

        tp = fp = tn = fn = 0
        for row in rows:
            true_attack = row["true_label"] in ("suspicious", "malicious")
            pred_attack = row["predicted_label"] in ("suspicious", "malicious")

            if true_attack and pred_attack:
                tp += 1
            elif not true_attack and pred_attack:
                fp += 1
            elif not true_attack and not pred_attack:
                tn += 1
            elif true_attack and not pred_attack:
                fn += 1

        total = tp + fp + tn + fn
        accuracy = safe_div(tp + tn, total)
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        f1 = round((2 * precision * recall) / (precision + recall), 2) if (precision + recall) else 0.0

        # -----------------------------
        # Unsupervised
        # -----------------------------
        if has_iso_score or has_anomaly_flag:
            avg_iso_expr = "AVG(COALESCE(iso_score, 0))" if has_iso_score else "0"
            anomaly_flag_expr = "SUM(CASE WHEN COALESCE(anomaly_flag, 0) = 1 THEN 1 ELSE 0 END)" if has_anomaly_flag else "0"
            high_risk_expr = "SUM(CASE WHEN COALESCE(iso_score, 0) >= 0.80 THEN 1 ELSE 0 END)" if has_iso_score else "0"
            normal_fit_expr = "SUM(CASE WHEN COALESCE(anomaly_flag, 0) = 0 THEN 1 ELSE 0 END)" if has_anomaly_flag else "0"

            cursor.execute(f"""
                SELECT
                    COUNT(*) AS total_rows,
                    {avg_iso_expr} AS avg_iso_score,
                    {anomaly_flag_expr} AS anomalies_flagged,
                    {high_risk_expr} AS high_risk_outliers,
                    {normal_fit_expr} AS normal_fit_count
                FROM api_logs
            """)
            unsup = cursor.fetchone()
        else:
            unsup = {
                "total_rows": 0,
                "avg_iso_score": 0,
                "anomalies_flagged": 0,
                "high_risk_outliers": 0,
                "normal_fit_count": 0
            }

        total_rows = unsup["total_rows"] or 0
        normal_pattern_fit = safe_div(unsup["normal_fit_count"] or 0, total_rows)

        # -----------------------------
        # MiTM / session behavior
        # -----------------------------
        mitm_alert_expr = "SUM(CASE WHEN LOWER(TRIM(COALESCE(mitm_class, 'normal'))) IN ('suspicious', 'malicious') THEN 1 ELSE 0 END)" if has_mitm_class else "0"
        replay_expr = "SUM(CASE WHEN COALESCE(replay_flag, 0) = 1 THEN 1 ELSE 0 END)" if has_replay_flag else "0"
        ip_expr = "SUM(CASE WHEN COALESCE(ip_changed, 0) = 1 THEN 1 ELSE 0 END)" if has_ip_changed else "0"
        ua_expr = "SUM(CASE WHEN COALESCE(user_agent_changed, 0) = 1 THEN 1 ELSE 0 END)" if has_user_agent_changed else "0"
        seq_expr = "SUM(CASE WHEN COALESCE(sequence_anomaly, 0) = 1 THEN 1 ELSE 0 END)" if has_sequence_anomaly else "0"
        hijack_expr = "SUM(CASE WHEN COALESCE(hijack_score, 0) >= 60 THEN 1 ELSE 0 END)" if has_hijack_score else "0"

        cursor.execute(f"""
            SELECT
                {mitm_alert_expr} AS mitm_alerts,
                {replay_expr} AS replay_events,
                {ip_expr} AS ip_changes,
                {ua_expr} AS user_agent_changes,
                {seq_expr} AS sequence_anomalies,
                {hijack_expr} AS high_hijack_events
            FROM api_logs
        """)
        mitm = cursor.fetchone()

        return jsonify({
            "success": True,
            "supervised": {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "true_positive": tp,
                "false_positive": fp,
                "true_negative": tn,
                "false_negative": fn,
                "sample_count": total
            },
            "unsupervised": {
                "avg_anomaly_score": round(float(unsup["avg_iso_score"] or 0), 4),
                "normal_pattern_fit": normal_pattern_fit,
                "anomalies_flagged": unsup["anomalies_flagged"] or 0,
                "high_risk_outliers": unsup["high_risk_outliers"] or 0
            },
            "mitm": {
                "mitm_alerts": mitm["mitm_alerts"] or 0,
                "replay_events": mitm["replay_events"] or 0,
                "ip_changes": mitm["ip_changes"] or 0,
                "user_agent_changes": mitm["user_agent_changes"] or 0,
                "sequence_anomalies": mitm["sequence_anomalies"] or 0,
                "high_hijack_events": mitm["high_hijack_events"] or 0
            }
        })

    except sqlite3.Error as e:
        return json_error("Database error while loading model performance", 500, e)
    except Exception as e:
        return json_error("Unexpected error while loading model performance", 500, e)
    finally:
        if conn:
            conn.close()

def get_table_columns(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return {row["name"] for row in cursor.fetchall()}


