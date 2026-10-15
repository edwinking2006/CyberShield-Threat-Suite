import os
import re
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# Enable CORS so Chrome Extension can make POST requests to Render API
CORS(app)

def analyze_url(target_url):
    """
    Advanced Heuristic & Rule-Based Phishing Detection Engine
    """
    score = 0
    reasons = []

    if not target_url:
        return {'is_phishing': False, 'risk_score': 0, 'status': 'SAFE', 'reasons': []}

    parsed = urlparse(target_url)
    domain = parsed.netloc.lower()

    # 1. Check URL Length
    if len(target_url) > 75:
        score += 25
        reasons.append("URL length is unusually long (>75 chars)")

    # 2. Check for IP Address instead of Domain
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, domain):
        score += 35
        reasons.append("Raw IP address used instead of valid Domain Name")

    # 3. Check for "@" Symbol (Redirection Trick)
    if "@" in target_url:
        score += 30
        reasons.append("Contains '@' symbol used for credential/URL spoofing")

    # 4. Check for Suspicious Keywords
    suspicious_keywords = [
        'login', 'verify', 'update', 'banking', 'secure', 'account',
        'free', 'bonus', 'claim', 'paypal', 'support', 'signin', 'confirm'
    ]
    matched_keywords = [kw for kw in suspicious_keywords if kw in target_url.lower()]
    if matched_keywords:
        score += len(matched_keywords) * 15
        reasons.append(f"Contains phishing target keywords: {', '.join(matched_keywords)}")

    # 5. Check Subdomains Count
    subdomains = domain.split('.')
    if len(subdomains) > 3:
        score += 20
        reasons.append("Excessive subdomains detected")

    # Final Risk Assessment
    risk_score = min(score, 100)
    is_phishing = risk_score >= 50

    return {
        'url': target_url,
        'is_phishing': is_phishing,
        'risk_score': risk_score,
        'status': 'DANGER' if is_phishing else 'SAFE',
        'reasons': reasons
    }

# ----------------- WEB DASHBOARD ROUTES ----------------- #

@app.route('/')
def home():
    # Renders the main web scanner UI
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def web_scan():
    # Route for the Web UI Form Submission
    target_url = request.form.get('url', '')
    result = analyze_url(target_url)
    return render_template('index.html', result=result, input_url=target_url)

# ----------------- CHROME EXTENSION API ENDPOINTS ----------------- #

@app.route('/scan-url', methods=['POST'])
def extension_scan():
    # Route for Chrome Extension API call
    data = request.get_json() or {}
    target_url = data.get('url', '')
    result = analyze_url(target_url)
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'online', 'service': 'CyberShield Threat Suite'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
