"""
MAS-CSI Real Lab Flask Application
Emits telemetry for registration, authentication, file transfer, and activity.
"""
from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)
BACKEND_URL = os.environ.get("MAS_BACKEND_URL", "http://localhost:8000")

@app.route("/")
def home():
    return jsonify({
        "service": "MAS-CSI Authorized Real Lab",
        "status": "ONLINE",
        "endpoints": ["/api/auth/login", "/api/auth/register", "/api/files/upload"]
    })

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "anonymous")
    try:
        requests.post(f"{BACKEND_URL}/api/events", json={
            "event_type": "login_attempt",
            "username": username,
            "source_ip": request.remote_addr or "127.0.0.1",
            "event_source": "Real Lab Local Service"
        }, timeout=2)
    except Exception:
        pass
    return jsonify({"status": "SUCCESS", "user": username})

if __name__ == "__main__":
    app.run(port=5000)
