from flask import Flask, jsonify
from routes.pages import pages_bp
from routes.dashboard import dashboard_bp
from routes.live_requests import live_requests_bp
from routes.attack_analytics import attack_analytics_bp
from routes.request_investigation import request_investigation_bp
from routes.model_performance import model_performance_bp
from routes.url_scanner import url_scanner_bp
from routes.email_alerts import email_alerts_bp

app = Flask(__name__, template_folder="templates")


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


app.register_blueprint(pages_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(live_requests_bp)
app.register_blueprint(attack_analytics_bp)
app.register_blueprint(request_investigation_bp)
app.register_blueprint(model_performance_bp)
app.register_blueprint(url_scanner_bp)
app.register_blueprint(email_alerts_bp)


if __name__ == "__main__":
    app.run(debug=True, port=5000)