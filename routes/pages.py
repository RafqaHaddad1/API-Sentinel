from flask import Blueprint, render_template

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def home():
    return render_template("Home.html")


@pages_bp.route("/live-requests")
def live_requests_page():
    return render_template("LiveMetrics.html")


@pages_bp.route("/attack-analytics")
def attack_analytics_page():
    return render_template("AttackAnalytics.html")


@pages_bp.route("/request-investigation")
def request_investigation_page():
    return render_template("RequestInvestigation.html")


@pages_bp.route("/model-performance")
def model_performance_page():
    return render_template("ModelPerformance.html")


@pages_bp.route("/url-scanner")
def url_scanner_page():
    return render_template("URLScanner.html")


@pages_bp.route("/email-alerts")
def email_alerts_page():
    return render_template("EmailAlerts.html")