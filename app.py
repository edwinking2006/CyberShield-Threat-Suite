import os
import re
import math
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

VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '056f4166e43eef4a12fd246944d73df93151cbd6a9aca7349afbc7837ceea64e')

# Load ML Model
MODEL_PATH = 'phishing_model.pkl'
ml_model = None
if os.path.exists(MODEL_PATH):
    try:
        ml_model = joblib.load(MODEL_PATH)
    except Exception as e:
        print(f"ML Model Load Error: {e}")

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def extract_features(target_url):
    parsed = urlparse(target_url if target_url.startswith('http') else 'http://' + target_url)
    domain = parsed.netloc.lower() or parsed.path.split('/')[0].lower()
    
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

    formatted_url = target_url.strip()
    if not formatted_url.startswith('http'):
        formatted_url = 'http://' + formatted_url

    parsed = urlparse(formatted_url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_path = path + ('?' + query if query else '')

    # 1. Hacked WordPress / CMS Directory Abuse Detection
    cms_hacked_patterns = ['/wp-includes/', '/wp-content/plugins/', '/wp-content/themes/', '/wp-admin/includes/']
    for pattern in cms_hacked_patterns:
        if pattern in path:
            score += 45
            reasons.append(f"Hacked CMS directory abuse detected ({pattern}) - Highly indicative of phishing upload on compromised website")

    # 2. Protocol / Sensitive Target Keywords in Path
    path_keywords = ['http', 'https', 'login', 'signin', 'owa', 'zimbra', 'exch', 'secure', 'verify', 'update', 'account', 'banking', 'paypal', 'office']
    matched_path_kw = [kw for kw in path_keywords if kw in path.split('/')]
    if matched_path_kw:
        score += len(matched_path_kw) * 25
        reasons.append(f"Suspicious path keyword(s) detected: {', '.join(matched_path_kw)}")

    # 3. Path Depth & Structure Anomalies
    path_segments = [seg for seg in path.split('/') if seg]
    if len(path_segments) >= 3:
        score += 20
        reasons.append(f"Deep directory structure detected ({len(path_segments)} sub-folders deep)")

    if len(full_path) > 25:
        score += 15
        reasons.append("Abnormally long URL path string often used to obscure phishing destinations")

    # 4. Entropy & IP Checks
    url_entropy = calculate_entropy(formatted_url)
    if url_entropy > 4.3:
        score += 20
        reasons.append(f"High Shannon Entropy in URL structure ({url_entropy:.2f} bits)")

    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", domain):
        score += 45
        reasons.append("Direct IP Host detected (no valid domain mapping)")

    # 5. ML Model Score Integration
    if ml_model:
        try:
            features = np.array([extract_features(formatted_url)])
            prob = ml_model.predict_proba(features)[0][1] * 100
            if prob >= 30:
                score += int(prob * 0.5)
                reasons.append(f"AI Neural/Tree Model Anomaly Score: {int(prob)}%")
        except Exception:
            pass

    # 6. VirusTotal Live Intel Integration
    if VT_API_KEY:
        try:
            headers = {"x-apikey": VT_API_KEY}
            import base64
            url_id = base64.urlsafe_b64encode(formatted_url.encode()).decode().strip("=")
            vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=3)
            if vt_res.status_code == 200:
                vt_data = vt_res.json()
                malicious_cnt = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                if malicious_cnt > 0:
                    score += 50 + (malicious_cnt * 10)
                    reasons.append(f"VirusTotal Global Engine flag: Malicious by {malicious_cnt} security vendors")
        except Exception:
            pass

    risk_score = min(score, 100)
    is_phishing = risk_score >= 35  # Dynamic Precision Threshold

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
        return render_template('index.html', qr_error="No image file uploaded", active_tab='qr')
    file = request.files['qr_image']
    try:
        np_img = np.frombuffer(file.read(), np.uint8)
        img = cv2.imdecode(np_img, cv2.IMREAD_COLOR)
        detector = cv2.QRCodeDetector()
        extracted_url, _, _ = detector.detectAndDecode(img)
        if not extracted_url:
            return render_template('index.html', qr_error="No valid QR code detected in image", active_tab='qr')
        result = analyze_url(extracted_url)
        return render_template('index.html', result=result, extracted_qr_url=extracted_url, active_tab='qr')
    except Exception as e:
        return render_template('index.html', qr_error=f"QR Decoder Exception: {str(e)}", active_tab='qr')

@app.route('/ip-geo', methods=['POST'])
def ip_geo():
    query_target = request.form.get('target', '').strip()
    try:
        ip = socket.gethostbyname(query_target.replace('http://', '').replace('https://', '').split('/')[0])
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        info_str = f"Target IP: {ip}\nCountry: {r.get('country')} ({r.get('countryCode')})\nRegion/City: {r.get('regionName')}, {r.get('city')}\nISP/Org: {r.get('isp')} / {r.get('org')}\nCoordinates: {r.get('lat')}, {r.get('lon')}"
        return render_template('index.html', ip_geo_result=info_str, active_tab='ipgeo')
    except Exception as e:
        return render_template('index.html', ip_geo_result=f"IP Geolocator Error: {str(e)}", active_tab='ipgeo')

@app.route('/vt-lookup', methods=['POST'])
def vt_lookup():
    resource = request.form.get('resource', '').strip()
    if not VT_API_KEY:
        return render_template('index.html', vt_result="VirusTotal API Key missing on server environment variables.", active_tab='vt')
    try:
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/files/{resource}", headers=headers, timeout=5)
        if res.status_code == 200:
            stats = res.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            out = f"Malicious: {stats.get('malicious')}\nSuspicious: {stats.get('suspicious')}\nUndetected: {stats.get('undetected')}\nHarmless: {stats.get('harmless')}"
        else:
            out = f"API Error / Resource not found: {res.status_code}"
        return render_template('index.html', vt_result=out, active_tab='vt')
    except Exception as e:
        return render_template('index.html', vt_result=f"VirusTotal Lookup Error: {str(e)}", active_tab='vt')

@app.route('/whois', methods=['POST'])
def whois_lookup():
    domain_name = request.form.get('domain', '').strip()
    try:
        w = whois.whois(domain_name)
        info_str = f"Domain: {w.domain_name}\nRegistrar: {w.registrar}\nCreation Date: {w.creation_date}\nExpiration Date: {w.expiration_date}\nEmails: {w.emails}\nCountry: {w.country}"
        return render_template('index.html', whois_info=info_str, active_tab='whois')
    except Exception as e:
        return render_template('index.html', whois_info=f"WHOIS Lookup failed: {str(e)}", active_tab='whois')

@app.route('/port-scan', methods=['POST'])
def port_scan():
    host = request.form.get('host', '').replace('http://', '').replace('https://', '').split('/')[0].strip()
    ports = [21, 22, 80, 443, 3306, 8080]
    results = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        res = s.connect_ex((host, port))
        results.append(f"Port {port:4d}: {'[ OPEN ]' if res == 0 else '[ CLOSED ]'}")
        s.close()
    return render_template('index.html', port_results="\n".join(results), active_tab='ports')

@app.route('/subdomains', methods=['POST'])
def subdomains():
    domain = request.form.get('domain', '').strip()
    subs = ['www', 'mail', 'ftp', 'admin', 'dev', 'api', 'test', 'blog', 'shop']
    found = []
    for sub in subs:
        target = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(target)
            found.append(f"✓ {target} -> {ip}")
        except:
            pass
    res_str = "\n".join(found) if found else "No common subdomains detected."
    return render_template('index.html', subdomain_results=res_str, active_tab='subdomains')

@app.route('/dns-lookup', methods=['POST'])
def dns_lookup():
    domain = request.form.get('domain', '').strip()
    try:
        ip = socket.gethostbyname(domain)
        all_info = socket.gethostbyname_ex(domain)
        res = f"A Record (IP Address): {ip}\nHost Mapping Details: {all_info[2]}"
    except Exception as e:
        res = f"DNS Lookup Error: {str(e)}"
    return render_template('index.html', dns_results=res, active_tab='dns')

@app.route('/ssl-check', methods=['POST'])
def ssl_check():
    domain = request.form.get('domain', '').replace('http://', '').replace('https://', '').split('/')[0].strip()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                res = f"Issued To: {subject.get('commonName')}\nIssued By: {issuer.get('organizationName')}\nValid From: {cert.get('notBefore')}\nValid Until: {cert.get('notAfter')}"
                return render_template('index.html', ssl_result=res, active_tab='ssl')
    except Exception as e:
        return render_template('index.html', ssl_result=f"SSL Audit Error: {str(e)}", active_tab='ssl')

@app.route('/headers-check', methods=['POST'])
def headers_check():
    url = request.form.get('url', '').strip()
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        r = requests.get(url, timeout=5)
        headers_str = "\n".join([f"{k}: {v}" for k, v in r.headers.items()])
        return render_template('index.html', headers_result=headers_str, active_tab='headers')
    except Exception as e:
        return render_template('index.html', headers_result=f"Headers Audit Error: {str(e)}", active_tab='headers')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
