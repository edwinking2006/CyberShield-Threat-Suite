import os
import re
import socket
import ssl
import requests
import joblib
import numpy as np
import cv2
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import whois

app = Flask(__name__)
CORS(app)

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

    # 1. ML Model Prediction
    if ml_model:
        features = np.array([extract_features(target_url)])
        prob = ml_model.predict_proba(features)[0][1] * 100
        if prob > 50:
            score += int(prob)
            reasons.append(f"AI Machine Learning Threat Engine confidence: {int(prob)}%")

    parsed = urlparse(target_url)
    domain = parsed.netloc.lower()

    # 2. Raw IP / Admin Path Detection
    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        score += 30
        reasons.append("Raw IP address used instead of valid domain name")

    # 3. Brand Spoofing Check
    brand_targets = ['paypal', 'google', 'facebook', 'instagram', 'netflix', 'amazon', 'sbi', 'hdfc']
    for brand in brand_targets:
        if brand in target_url.lower() and not domain.endswith(f".{brand}.com") and domain != f"{brand}.com":
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
    return render_template('index.html', active_tab='url')

@app.route('/scan', methods=['POST'])
def web_scan():
    target_url = request.form.get('url', '')
    result = analyze_url(target_url)
    return render_template('index.html', result=result, input_url=target_url, active_tab='url')

@app.route('/scan-url', methods=['POST'])
def extension_scan():
    data = request.get_json() or {}
    target_url = data.get('url', '')
    result = analyze_url(target_url)
    return jsonify(result)

@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    if 'qr_image' not in request.files:
        return render_template('index.html', qr_error="No image uploaded", active_tab='qr')
    file = request.files['qr_image']
    try:
        np_img = np.frombuffer(file.read(), np.uint8)
        img = cv2.imdecode(np_img, cv2.IMREAD_COLOR)
        detector = cv2.QRCodeDetector()
        extracted_url, _, _ = detector.detectAndDecode(img)
        if not extracted_url:
            return render_template('index.html', qr_error="No valid QR code found in image", active_tab='qr')
        result = analyze_url(extracted_url)
        return render_template('index.html', result=result, extracted_qr_url=extracted_url, active_tab='qr')
    except Exception as e:
        return render_template('index.html', qr_error=f"QR Error: {str(e)}", active_tab='qr')

@app.route('/whois', methods=['POST'])
def whois_lookup():
    domain_name = request.form.get('domain', '')
    try:
        w = whois.whois(domain_name)
        return render_template('index.html', whois_info=str(w), active_tab='whois')
    except Exception as e:
        return render_template('index.html', whois_info=f"WHOIS Failed: {str(e)}", active_tab='whois')

@app.route('/port-scan', methods=['POST'])
def port_scan():
    host = request.form.get('host', '').replace('http://', '').replace('https://', '').split('/')[0]
    ports = [21, 22, 80, 443, 3306, 8080]
    results = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        res = s.connect_ex((host, port))
        results.append(f"Port {port}: {'OPEN' if res == 0 else 'CLOSED'}")
        s.close()
    return render_template('index.html', port_results="\n".join(results), active_tab='ports')

@app.route('/subdomains', methods=['POST'])
def subdomains():
    domain = request.form.get('domain', '')
    subs = ['www', 'mail', 'ftp', 'admin', 'dev', 'api', 'test', 'blog', 'shop']
    found = []
    for sub in subs:
        target = f"{sub}.{domain}"
        try:
            socket.gethostbyname(target)
            found.append(f"✓ Found Subdomain: {target}")
        except:
            pass
    res_str = "\n".join(found) if found else "No standard subdomains found."
    return render_template('index.html', subdomain_results=res_str, active_tab='subdomains')

@app.route('/dns-lookup', methods=['POST'])
def dns_lookup():
    domain = request.form.get('domain', '')
    try:
        ip = socket.gethostbyname(domain)
        all_info = socket.gethostbyname_ex(domain)
        res = f"A Record (IP): {ip}\nHost Info: {all_info}"
    except Exception as e:
        res = f"DNS Lookup Error: {str(e)}"
    return render_template('index.html', dns_results=res, active_tab='dns')

@app.route('/ssl-check', methods=['POST'])
def ssl_check():
    domain = request.form.get('domain', '')
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return render_template('index.html', ssl_result=str(cert), active_tab='ssl')
    except Exception as e:
        return render_template('index.html', ssl_result=f"SSL Error: {str(e)}", active_tab='ssl')

@app.route('/headers-check', methods=['POST'])
def headers_check():
    url = request.form.get('url', '')
    try:
        r = requests.get(url, timeout=5)
        return render_template('index.html', headers_result=str(dict(r.headers)), active_tab='headers')
    except Exception as e:
        return render_template('index.html', headers_result=f"Headers Error: {str(e)}", active_tab='headers')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
