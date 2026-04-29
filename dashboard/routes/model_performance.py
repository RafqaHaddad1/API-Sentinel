
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
                "avg_anomaly_score": round(float(row["avg_iso_score"] or 0), 4),
                "normal_pattern_fit": safe_div(row["normal_fit_count"] or 0, total_rows),
                "anomalies_flagged": row["anomalies_flagged"] or 0,
                "high_risk_outliers": row["high_risk_outliers"] or 0
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

        cursor.execute("""
            SELECT *
            FROM model_current_metrics
            WHERE model_name IN ('rf_model', 'iso_model', 'mitm_autoencoder')
        """)
        rows = cursor.fetchall()

        models = {}
        for row in rows:
            models[row["model_name"]] = dict(row)

        def parse_metrics(model_name):
            row = models.get(model_name)
            if not row:
                return {}

            metrics_json = row.get("metrics_json")
            if metrics_json:
                import json
                try:
                    return json.loads(metrics_json)
                except Exception:
                    return {}

            return {}

        rf = parse_metrics("rf_model")
        iso = parse_metrics("iso_model")
        mitm_ae = parse_metrics("mitm_autoencoder")

        rf_cm = rf.get("confusion_matrix", {})
        iso_cm = iso.get("confusion_matrix", {})
        mitm_cm = mitm_ae.get("confusion_matrix", {})

        # -----------------------------
        # Risk Score Distribution
        # Low Risk:    0 - 39
        # Medium Risk: 40 - 69
        # High Risk:   70+
        # -----------------------------
        cursor.execute("""
            SELECT
                COUNT(*) AS total_requests,

                SUM(CASE 
                    WHEN COALESCE(fusion_risk_score, rule_risk_score, supervised_score, iso_score, mitm_score, 0) < 0.4
                    THEN 1 ELSE 0 
                END) AS low_risk,

                SUM(CASE 
                    WHEN COALESCE(fusion_risk_score, rule_risk_score, supervised_score, iso_score, mitm_score, 0) >= 0.4
                     AND COALESCE(fusion_risk_score, rule_risk_score, supervised_score, iso_score, mitm_score, 0) < 0.7
                    THEN 1 ELSE 0 
                END) AS medium_risk,

                SUM(CASE 
                    WHEN COALESCE(fusion_risk_score, rule_risk_score, supervised_score, iso_score, mitm_score, 0) >= 0.7
                    THEN 1 ELSE 0 
                END) AS high_risk

            FROM api_logs
        """)
        
        risk_row = cursor.fetchone()

        total_risk = risk_row["total_requests"] or 0
        low_risk = risk_row["low_risk"] or 0
        medium_risk = risk_row["medium_risk"] or 0
        high_risk = risk_row["high_risk"] or 0
        cursor.execute("""
    SELECT
        COUNT(*) AS total,

        SUM(CASE WHEN COALESCE(iso_score, 0) < 0.4 THEN 1 ELSE 0 END) AS low,

        SUM(CASE 
            WHEN COALESCE(iso_score, 0) >= 0.4 
             AND COALESCE(iso_score, 0) < 0.7 
            THEN 1 ELSE 0 
        END) AS medium,

        SUM(CASE WHEN COALESCE(iso_score, 0) >= 0.7 THEN 1 ELSE 0 END) AS high

    FROM api_logs
""")

        unsup_risk_row = cursor.fetchone()

        unsup_low = unsup_risk_row["low"] or 0
        unsup_medium = unsup_risk_row["medium"] or 0
        unsup_high = unsup_risk_row["high"] or 0
        unsup_total = unsup_risk_row["total"] or 0

        cursor.execute("""
    SELECT
        SUM(CASE WHEN COALESCE(replay_flag, 0) = 1 THEN 1 ELSE 0 END) AS replay_events,
        SUM(CASE WHEN COALESCE(ip_changed, 0) = 1 THEN 1 ELSE 0 END) AS ip_changes,
        SUM(CASE WHEN COALESCE(user_agent_changed, 0) = 1 THEN 1 ELSE 0 END) AS user_agent_changes,
        SUM(CASE WHEN COALESCE(sequence_anomaly, 0) = 1 THEN 1 ELSE 0 END) AS sequence_anomalies
    FROM api_logs
""")
        mitm_events = cursor.fetchone()

        return jsonify({
            "success": True,

            "risk_distribution": {
                "low_risk": low_risk,
                "medium_risk": medium_risk,
                "high_risk": high_risk,
                "low_percent": safe_div(low_risk, total_risk),
                "medium_percent": safe_div(medium_risk, total_risk),
                "high_percent": safe_div(high_risk, total_risk),
                "total_requests": total_risk
            },

            "supervised": {
                "accuracy": round((rf.get("accuracy") or 0) * 100, 2),
                "precision": round((rf.get("precision") or 0) * 100, 2),
                "recall": round((rf.get("recall") or 0) * 100, 2),
                "f1_score": round((rf.get("f1") or 0) * 100, 2),

                "true_positive": rf_cm.get("tp", 0),
                "false_positive": rf_cm.get("fp", 0),
                "true_negative": rf_cm.get("tn", 0),
                "false_negative": rf_cm.get("fn", 0),

                "sample_count": rf.get("n_samples", 0),
                "threshold": rf.get("threshold", 0),
                "roc_auc": round((rf.get("roc_auc") or 0) * 100, 2)
            },

            "unsupervised": {
                "avg_anomaly_score": round(iso.get("threshold") or 0, 4),
                "normal_pattern_fit": round((iso.get("accuracy") or 0) * 100, 2),
                "anomalies_flagged": iso_cm.get("tp", 0) + iso_cm.get("fp", 0),
                "high_risk_outliers": iso_cm.get("tp", 0),
                
                "accuracy": round((iso.get("accuracy") or 0) * 100, 2),
                "precision": round((iso.get("precision") or 0) * 100, 2),
                "recall": round((iso.get("recall") or 0) * 100, 2),
                "f1_score": round((iso.get("f1") or 0) * 100, 2)
            },
            "unsupervised_risk": {
                "low": unsup_low,
                "medium": unsup_medium,
                "high": unsup_high,
                "total": unsup_total
            },
            "mitm": {
                "mitm_alerts": mitm_cm.get("tp", 0) + mitm_cm.get("fp", 0),
                "replay_events": mitm_events["replay_events"] or 0,
                "ip_changes": mitm_events["ip_changes"] or 0,
                "user_agent_changes": mitm_events["user_agent_changes"] or 0,
                "sequence_anomalies": mitm_events["sequence_anomalies"] or 0,

                "accuracy": round((mitm_ae.get("accuracy") or 0) * 100, 2),
                "precision": round((mitm_ae.get("precision") or 0) * 100, 2),
                "recall": round((mitm_ae.get("recall") or 0) * 100, 2),
                "f1_score": round((mitm_ae.get("f1") or 0) * 100, 2)
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


