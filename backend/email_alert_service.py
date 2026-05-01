from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from settings import BACKEND_BASE_URL, CSV_LOG_PATH, DB_PATH, REQUEST_TIMEOUT
import csv
import json
import sqlite3
import time
import uuid

def save_email_alert_history(
    recipient,
    severity,
    trigger,
    ip_address,
    endpoint,
    delivery_status,
    error_message=None,
    email_html=None,
    threat_score=None
):
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO email_alert_history (
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
            ) VALUES (
                datetime('now'),
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            recipient,
            severity,
            trigger,
            ip_address,
            endpoint,
            delivery_status,
            error_message,
            email_html,
            threat_score
        ))

        conn.commit()

    except Exception as e:
        print("save_email_alert_history error:", e)
    finally:
        if conn:
            conn.close()

def map_severity(predicted_class):
    predicted_class = (predicted_class or "normal").lower()

    if predicted_class == "malicious":
        return "malicious"
    elif predicted_class == "suspicious":
        return "suspicious"
    else:
        return "normal"

EMAIL_SENDER   = "sentinel.apisec@gmail.com"
EMAIL_PASSWORD = "#####"

SEVERITY_CONFIG = {
    "malicious": {
        "label": "MALICIOUS",
        "color": "#A32D2D",
        "bg": "#FCEBEB",
        "border": "#E24B4A"
    },
    "suspicious": {
        "label": "SUSPICIOUS",
        "color": "#854F0B",
        "bg": "#FAEEDA",
        "border": "#EF9F27"
    },
    "normal": {
        "label": "NORMAL",
        "color": "#185FA5",
        "bg": "#E6F1FB",
        "border": "#378ADD"
    }
}

def _detail_cell(label, value, mono=False):
    font = "font-family:monospace;" if mono else ""
    return f"""
    <td style="padding:12px 14px;vertical-align:top;">
      <div style="font-size:10px;color:#888780;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:3px;">{label}</div>
      <div style="font-size:13px;color:#2C2C2A;font-weight:500;{font}">{value or "—"}</div>
    </td>"""

def _method_badge(method):
    colors = {
        "GET":    ("#185FA5","#E6F1FB","#378ADD"),
        "POST":   ("#3B6D11","#EAF3DE","#639922"),
        "PUT":    ("#854F0B","#FAEEDA","#EF9F27"),
        "DELETE": ("#A32D2D","#FCEBEB","#E24B4A"),
        "PATCH":  ("#3C3489","#EEEDFE","#7F77DD"),
    }
    c, bg, br = colors.get(method.upper(), ("#5F5E5A","#F1EFE8","#B4B2A9"))
    return f'<span style="font-size:11px;font-weight:700;padding:3px 8px;border-radius:4px;border:1px solid {br};background:{bg};color:{c};font-family:monospace;">{method.upper()}</span>'

def _status_badge(status):
    code = int(status)
    if code < 300:   c,bg,br = "#3B6D11","#EAF3DE","#639922"
    elif code < 400: c,bg,br = "#854F0B","#FAEEDA","#EF9F27"
    else:            c,bg,br = "#A32D2D","#FCEBEB","#E24B4A"
    return f'<span style="font-size:11px;font-weight:700;padding:3px 8px;border-radius:4px;border:1px solid {br};background:{bg};color:{c};font-family:monospace;">{status}</span>'


def send_email_alert(
    subject, body, severity="normal", trigger="", ip_address="", endpoint="",
    method="", status_code="", user_agent="", geo_country="", geo_city="",  risk_score=0.0
):
    print("\n===== EMAIL FUNCTION CALLED =====")
    conn = None
    cfg = SEVERITY_CONFIG.get(severity.lower(), SEVERITY_CONFIG["normal"])
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        score = int(round(float(risk_score) * 100))
    except Exception:
        score = 0


    method_cell = ""
    if method or status_code:
        method_html  = _method_badge(method)  if method      else "—"
        status_html  = _status_badge(str(status_code)) if status_code else "—"
        method_cell  = f"""
        <tr>
          <td style="padding:12px 14px;border-top:0.5px solid #D3D1C7;vertical-align:top;">
            <div style="font-size:10px;color:#888780;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px;">Method</div>
            {method_html}
          </td>
          <td style="padding:12px 14px;border-top:0.5px solid #D3D1C7;border-left:0.5px solid #D3D1C7;vertical-align:top;">
            <div style="font-size:10px;color:#888780;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:5px;">Status code</div>
            {status_html}
          </td>
        </tr>"""

    geo_display = ", ".join(filter(None, [geo_city, geo_country])) or "—"
    ua_display  = (user_agent[:60] + "…") if len(user_agent) > 60 else (user_agent or "—")

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel Alert</title>
</head>

<body style="margin:0;padding:0;background:#F1EFE8;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F1EFE8;padding:32px 0;">
    <tr>
      <td align="center">

        <table width="600" cellpadding="0" cellspacing="0"
               style="background:#ffffff;border-radius:12px;overflow:hidden;border:0.5px solid #D3D1C7;">

          <!-- Header -->
          <tr>
            <td style="background:#1a1a2e;padding:24px 28px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td>
                    <span style="font-size:18px;font-weight:700;color:#fff;letter-spacing:1px;">
                      SENTINEL
                    </span>
                    <span style="font-size:11px;color:#9F9FBF;margin-left:8px;">
                      API Security Monitor
                    </span>
                  </td>
                  <td align="right">
                    <span style="background:{cfg['bg']};color:{cfg['color']};font-size:11px;font-weight:700;
                                 padding:5px 12px;border-radius:20px;border:1px solid {cfg['border']};letter-spacing:0.5px;">
                      {cfg['label']}
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Alert Title -->
          <tr>
            <td style="background:{cfg['bg']};border-left:4px solid {cfg['border']};padding:14px 28px;">
              <p style="margin:0;font-size:11px;color:{cfg['color']};font-weight:600;
                        text-transform:uppercase;letter-spacing:0.5px;">
                Security alert triggered
              </p>
              <p style="margin:4px 0 0;font-size:17px;font-weight:700;color:#2C2C2A;">
                {trigger or "Anomaly Detected"}
              </p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:24px 28px;">

              <!-- Description -->
              <p style="margin:0 0 20px;font-size:14px;color:#444441;line-height:1.6;">
                {body}
              </p>

              <!-- Detail Grid -->
              <table width="100%" cellpadding="0" cellspacing="0"
                     style="background:#F1EFE8;border-radius:8px;border:0.5px solid #D3D1C7;overflow:hidden;margin-bottom:20px;">

                <!-- Row 1 -->
                <tr>
                  <td style="width:50%;padding:12px 14px;vertical-align:top;">
                    <div style="font-size:10px;color:#888780;text-transform:uppercase;margin-bottom:3px;">Timestamp</div>
                    <div style="font-size:13px;font-weight:600;color:#2C2C2A;">{now}</div>
                  </td>

                  <td style="width:50%;padding:12px 14px;border-left:0.5px solid #D3D1C7;vertical-align:top;">
                    <div style="font-size:10px;color:#888780;text-transform:uppercase;margin-bottom:3px;">Severity</div>
                    <div style="font-size:13px;font-weight:700;color:{cfg['color']};">{cfg['label']}</div>
                  </td>
                </tr>

                <!-- Row 2 -->
                <tr>
                  <td style="padding:12px 14px;border-top:0.5px solid #D3D1C7;">
                    <div style="font-size:10px;color:#888780;text-transform:uppercase;margin-bottom:3px;">Source IP</div>
                    <div style="font-size:13px;font-family:monospace;">{ip_address}</div>
                  </td>

                  <td style="padding:12px 14px;border-top:0.5px solid #D3D1C7;border-left:0.5px solid #D3D1C7;">
                    <div style="font-size:10px;color:#888780;text-transform:uppercase;margin-bottom:3px;">Endpoint</div>
                    <div style="font-size:13px;font-family:monospace;">{endpoint}</div>
                  </td>
                </tr>

                <!-- Row 3 -->
                <tr>
                  <td style="padding:12px 14px;border-top:0.5px solid #D3D1C7;">
                    <div style="font-size:10px;color:#888780;text-transform:uppercase;margin-bottom:3px;">Method</div>
                    <div style="font-size:13px;font-family:monospace;">{method}</div>
                  </td>

                  <td style="padding:12px 14px;border-top:0.5px solid #D3D1C7;border-left:0.5px solid #D3D1C7;">
                    <div style="font-size:10px;color:#888780;text-transform:uppercase;margin-bottom:3px;">User Agent</div>
                    <div style="font-size:13px;">{ua_display}</div>
                  </td>
                </tr>

              </table>

              <!-- CTA -->
              <table cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:#1a1a2e;border-radius:8px;padding:11px 22px;">
                    <a href="#" style="text-decoration:none;">
                      <span style="color:#ffffff;font-size:13px;font-weight:600;">
                        View dashboard →
                      </span>
                    </a>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="border-top:0.5px solid #D3D1C7;padding:14px 28px;background:#F1EFE8;">
              <p style="margin:0;font-size:11px;color:#888780;line-height:1.6;">
                This alert was generated automatically by Sentinel API Security Monitor.<br>
                Do not reply to this email. To manage alerts, visit your dashboard.
              </p>
            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>
</body>
</html>
"""

    plain_body = (
        f"SENTINEL — API Security Monitor\n{'='*42}\n"
        f"Alert     : {trigger or 'Anomaly Detected'}\n"
        f"Time      : {now}\n"
        f"IP        : {ip_address or 'N/A'}\n"
        f"Endpoint  : {endpoint or 'N/A'}\n"
        f"Method    : {method or 'N/A'}  Status: {status_code or 'N/A'}\n"
        f"Location  : {geo_display}\n"
        f"User-Agent: {user_agent or 'N/A'}\n\n"
        f"{body}\n"
    )

    recipients = []

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT email
            FROM email_alert_recipients
            WHERE is_active = 1
        """)

        rows = cursor.fetchall()

        recipients = [row["email"].strip() for row in rows if row["email"]]

        print("📧 Active recipients:", recipients)

        if not recipients:
            print("⚠️ No active email recipients configured")
            return False

        success_count = 0

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo()
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)

            for recipient in recipients:
                try:
                    msg = MIMEMultipart("alternative")
                    msg["Subject"] = f"[SENTINEL] {cfg['label']} — {trigger or 'Security Alert'}"
                    msg["From"] = EMAIL_SENDER
                    msg["To"] = recipient

                    msg.attach(MIMEText(plain_body, "plain"))
                    msg.attach(MIMEText(html_body, "html"))

                    server.send_message(msg)

                    save_email_alert_history(
                        recipient=recipient,
                        severity=severity,
                        trigger=trigger,
                        ip_address=ip_address,
                        endpoint=endpoint,
                        delivery_status="success",
                        email_html=html_body,
                        threat_score=score
                    )

                    print("✅ Email sent to", recipient)
                    success_count += 1

                except Exception as send_error:
                    print(f"❌ Email failed for {recipient}:", send_error)

                    save_email_alert_history(
                        recipient=recipient,
                        severity=severity,
                        trigger=trigger,
                        ip_address=ip_address,
                        endpoint=endpoint,
                        delivery_status="failed",
                        error_message=str(send_error),
                        email_html=html_body,
                        threat_score=score
                    )

        return success_count > 0

    except Exception as e:
        print("❌ Email system error:", e)

        save_email_alert_history(
            recipient=None,
            severity=severity,
            trigger=trigger,
            ip_address=ip_address,
            endpoint=endpoint,
            delivery_status="failed",
            error_message=str(e),
            email_html=html_body,
            threat_score=score
        )

        return False

    finally:
        if conn:
            conn.close()
