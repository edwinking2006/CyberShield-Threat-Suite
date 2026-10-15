import os
import re
import requests
import joblib
import numpy as np
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '056f4166e43eef4a12fd246944d73df93151cbd6a9aca7349afbc7837ceea64e')

# Load ML Model if exists
MODEL_PATH = 'phishing_model.pkl'
ml_model = None
if os.path.exists(MODEL_PATH):
    try:
        ml_model = joblib.load(MODEL_PATH)
        print("✅ ML Model Loaded Successfully")
    except Exception as e:
        print(f"ML Model Load Error: {e}")

def extract_features(target_url):
    parsed = urlparse(target_url)
    domain = parsed.netloc.lower()
    
    url_len = len(target_url)
    domain_len = len(domain)
    count_dots = target_url.count('.')
    count_hyphens = target_url.count('-')
    is_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0
    count_at = 1 if "@" in target_url else 0
    has_https = 1 if parsed.scheme == 'https' else 0
    num_subdomains = len(domain.split('.'))
    
    return [url_len, domain_len, count_dots, count_hyphens, is_ip, count_at, has_https, num_subdomains]

def check_virustotal(target_url):
    if not VT_API_KEY:
        return False, "VirusTotal API Key not configured"
    try:
        headers = {"x-apikey": VT_API_KEY}
        import base64
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            if malicious_count > 0:
                return True, f"Flagged by {malicious_count} security engines on VirusTotal"
    except Exception as e:
        print(f"VT Error: {e}")
    return False, None

def analyze_url(target_url):
    score = 0
    reasons = []

    if not target_url:
        return {'is_phishing': False, 'risk_score': 0, 'status': 'SAFE', 'reasons': []}

    # 1. ML AI Prediction
    if ml_model:
        features = np.array([extract_features(target_url)])
        prediction = ml_model.predict(features)[0]
        prob = ml_model.predict_proba(features)[0][1] * 100
        if prediction == 1:
            score += int(prob * 0.5)
            reasons.append(f"AI Machine Learning Engine predicted high anomaly ({int(prob)}% confidence)")

    # 2. VirusTotal API Lookup
    is_vt_malicious, vt_msg = check_virustotal(target_url)
    if is_vt_malicious:
        score += 70
        reasons.append(vt_msg)

    # 3. Domain Spoofing Checks
    parsed = urlparse(target_url)
    domain = parsed.netloc.lower()
    brand_targets = ['paypal', 'google', 'facebook', 'instagram', 'netflix', 'amazon', 'sbi', 'hdfc']
    for brand in brand_targets:
        if brand in domain and not domain.endswith(f".{brand}.com") and domain != f"{brand}.com":
            score += 40
            reasons.append(f"Spoofing indicator detected for brand '{brand}'")

    risk_score = min(score, 100)
    is_phishing = risk_score >= 50

    return {
        'url': target_url,
        'is_phishing': is_phishing,
        'risk_score': risk_score,
        'status': 'DANGER' if is_phishing else 'SAFE',
        'reasons': reasons
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def web_scan():
    target_url = request.form.get('url', '')
    result = analyze_url(target_url)
    return render_template('index.html', result=result, input_url=target_url)

@app.route('/scan-url', methods=['POST'])
def extension_scan():
    data = request.get_json() or {}
    target_url = data.get('url', '')
    result = analyze_url(target_url)
    return jsonify(result)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
