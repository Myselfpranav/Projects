import re
import requests
import json
import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = "cyber_security_secret_guard"

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5-coder:1.5b"

# Global In-Memory Database
GUEST_ACCOUNTS = {
    "guest_user": "guest123"
}
GUEST_REGISTRY = [
    {"username": "guest_user", "org": "BCA Evaluator", "timestamp": "System Pre-set"}
]

# Synchronized State Tracking Layer
CURRENT_USER = {
    "name": "Anonymous",
    "role": "guest",
    "scan_count": 0,
    "history": [70, 75, 80, 85], # Kept primitive for dashboard SVG graph points
    "detailed_history": [        # Populated for the history table template module
        {"timestamp": "2026-05-22 14:23:11", "code_snippet": "def connect(): pass = '1234'", "score": 70},
        {"timestamp": "2026-05-22 14:45:02", "code_snippet": "import os; os.system(input)", "score": 75},
        {"timestamp": "2026-05-22 15:02:40", "code_snippet": "print('Secure Sandbox Application')", "score": 80},
        {"timestamp": "2026-05-22 15:15:19", "code_snippet": "hashlib.sha256(data).hexdigest()", "score": 85}
    ],
    "latest_score": 85,
    "latest_report": "System initialized. Run a code scan to view active fix suggestions."
}

GUEST_MAX_SCANS = 99

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == "admin_root" and password == "password":
            CURRENT_USER["name"] = "Admin Root"
            CURRENT_USER["role"] = "admin"
            return redirect(url_for('admin_portal'))
        else:
            return render_template('admin_login.html', error="Invalid Administrative Credentials")
    return render_template('admin_login.html')

@app.route('/guest/login', methods=['GET', 'POST'])
def guest_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in GUEST_ACCOUNTS and GUEST_ACCOUNTS[username] == password:
            CURRENT_USER["name"] = username
            CURRENT_USER["role"] = "guest"
            CURRENT_USER["scan_count"] = 0
            CURRENT_USER["history"] = [60, 65, 55, 75]
            CURRENT_USER["detailed_history"] = []
            CURRENT_USER["latest_score"] = 75
            CURRENT_USER["latest_report"] = "Session started. Ready for code analysis."
            return redirect(url_for('editor'))
        else:
            return render_template('guest_login.html', error="Access Denied: Incorrect Handle or Passphrase")
    return render_template('guest_login.html')

@app.route('/guest/register', methods=['GET', 'POST'])
def guest_register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        org = request.form.get('organization')
        
        if username in GUEST_ACCOUNTS:
            return render_template('guest_register.html', error="Handle already taken.")
        
        GUEST_ACCOUNTS[username] = password
        GUEST_REGISTRY.append({"username": username, "org": org, "timestamp": "Self-Enrolled"})
        
        CURRENT_USER["name"] = username
        CURRENT_USER["role"] = "guest"
        CURRENT_USER["scan_count"] = 0
        CURRENT_USER["history"] = [40, 50, 45, 60]
        CURRENT_USER["detailed_history"] = []
        CURRENT_USER["latest_score"] = 60
        CURRENT_USER["latest_report"] = "Registration profile generated. Awaiting first scan submission."
        return redirect(url_for('editor'))
    return render_template('guest_register.html')

@app.route('/admin-portal')
def admin_portal():
    if CURRENT_USER["role"] != "admin":
        return "Unauthorized System Node Access", 403
    return render_template('admin_portal.html', guests=GUEST_REGISTRY)

@app.route('/editor')
def editor():
    return render_template('editor.html', user=CURRENT_USER, max_scans=GUEST_MAX_SCANS)

@app.route('/dashboard')
def dashboard():
    latest_score = CURRENT_USER.get("latest_score", 0)
    
    if latest_score >= 85:
        security_level = "Secure (Low Risk Tier)"
    elif latest_score >= 70:
        security_level = "Elevated Operational Risk"
    elif latest_score >= 45:
        security_level = "High Vulnerability Threat"
    else:
        security_level = "Critical System Compromise"
        
    history = CURRENT_USER.get("history", [])
    avg_score = sum(history) / len(history) if history else 0
    
    performance_params = {
        "current_score": latest_score,
        "average_historical_score": round(avg_score, 1),
        "total_scans_performed": CURRENT_USER.get("scan_count", 0),
        "peak_security_score": max(history) if history else 0,
        "lowest_security_score": min(history) if history else 0
    }
    
    fix_suggestion = CURRENT_USER.get("latest_report", "No code data found in active profile memory.")

    return render_template(
        'dashboard.html', 
        user=CURRENT_USER,
        security_level=security_level,
        performance_params=performance_params,
        fix_suggestion=fix_suggestion
    )

@app.route('/guest/history')
def guest_history():
    # Serves the history template populated directly from active global runtime matrix data
    return render_template(
        'guest_history.html', 
        user_name=CURRENT_USER["name"], 
        history_records=CURRENT_USER.get("detailed_history", [])
    )

@app.route('/scan', methods=['POST'])
def scan_code():
    data = request.json or {}
    user_code = data.get("code", "")
    
    if CURRENT_USER["role"] == "guest":
        if CURRENT_USER["scan_count"] >= GUEST_MAX_SCANS:
            return jsonify({
                "limit_exceeded": True,
                "ai_security_report": "⚠️ POLICY VIOLATION: Scan limit reached.",
                "security_score": 0,
                "regex_secret_alert": False
            }), 403
        CURRENT_USER["scan_count"] += 1

    secret_pattern = r'(password|passwd|api_key|secret|token)\s*=\s*[\'"][^\'"]+[\'"]'
    secret_found = bool(re.search(secret_pattern, user_code, re.IGNORECASE))

    system_prompt = (
        "You are an expert security code auditor. Analyze this source code template.\n"
        f"Source Code:\n{user_code}"
    )
    
    try:
        response = requests.post(OLLAMA_URL, json={"model": MODEL_NAME, "prompt": system_prompt, "stream": False}, timeout=30)
        ai_analysis = response.json().get("response", "Processing breakdown.")
        
        score = 95
        if secret_found: score -= 25
        if "vulnerability" in ai_analysis.lower() or "injection" in ai_analysis.lower(): score -= 45
        if score < 0: score = 10
    except Exception:
        ai_analysis = "⚠️ Offline inference link unavailable. Check Ollama system terminal."
        score = 0

    # Unified Multi-Data Tracking Cache Saves
    CURRENT_USER["latest_score"] = score
    CURRENT_USER["latest_report"] = ai_analysis
    CURRENT_USER["history"].append(score)
    
    # Save formatted entry out to history table timeline tracking
    timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    CURRENT_USER["detailed_history"].append({
        "timestamp": timestamp_str,
        "code_snippet": user_code[:80] + "..." if len(user_code) > 80 else user_code,
        "score": score
    })

    return jsonify({
        "limit_exceeded": False,
        "regex_secret_alert": secret_found,
        "ai_security_report": ai_analysis,
        "security_score": score,
        "remaining_scans": GUEST_MAX_SCANS - CURRENT_USER["scan_count"] if CURRENT_USER["role"] == "guest" else "Unlimited"
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)