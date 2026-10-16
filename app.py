import os
import re
import socket
import ssl
import requests
import joblib
import numpy as np
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from PIL import Image
from pyzbar.pyzbar import decode
import whois

app = Flask(__name__)
CORS(app)

VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '056f4166e43eef4a12fd246944d73df93151cbd6a9aca7349afbc7837ceea64e')

MODEL_PATH = 'phishing_model.pkl'
ml_model = None
if os.path.exists(MODEL_PATH):
    try:
        ml_model = joblib.load(MODEL_PATH)
    except Exception as e:
        print(f"ML Model Error: {e}")

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

def analyze_url(target_url):
    score = 0
    reasons = []
    if not target_url:
        return {'is_phishing': False, 'risk_score': 0, 'status': 'SAFE', 'reasons': []}

    if ml_model:
        features = np.array([extract_features(target_url)])
        prediction = ml_model.predict(features)[0]
        prob = ml_model.predict_proba(features)[0][1] * 100
        if prediction == 1:
            score += int(prob * 0.5)
            reasons.append(f"AI Machine Learning Threat Engine confidence: {int(prob)}%")

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

@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    if 'qr_image' not in request.files:
        return render_template('index.html', qr_error="No image uploaded")
    file = request.files['qr_image']
    try:
        img = Image.open(file)
        decoded_objs = decode(img)
        if not decoded_objs:
            return render_template('index.html', qr_error="No valid QR code found in image")
        extracted_url = decoded_objs[0].data.decode('utf-8')
        result = analyze_url(extracted_url)
        return render_template('index.html', result=result, extracted_qr_url=extracted_url)
    except Exception as e:
        return render_template('index.html', qr_error=f"QR Decode Error: {str(e)}")

@app.route('/whois', methods=['POST'])
def whois_lookup():
    domain_name = request.form.get('domain', '')
    try:
        w = whois.whois(domain_name)
        return render_template('index.html', whois_info=str(w))
    except Exception as e:
        return render_template('index.html', whois_info=f"WHOIS Lookup failed: {str(e)}")

@app.route('/ssl-check', methods=['POST'])
def ssl_check():
    domain = request.form.get('domain', '')
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return render_template('index.html', ssl_result=str(cert))
    except Exception as e:
        return render_template('index.html', ssl_result=f"SSL Check Error: {str(e)}")

@app.route('/headers-check', methods=['POST'])
def headers_check():
    url = request.form.get('url', '')
    try:
        r = requests.get(url, timeout=5)
        return render_template('index.html', headers_result=str(dict(r.headers)))
    except Exception as e:
        return render_template('index.html', headers_result=f"Headers Audit Error: {str(e)}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
