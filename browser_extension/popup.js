const BACKEND_URL = "https://cybershield-threat-suite.onrender.com/scan-url";

document.addEventListener('DOMContentLoaded', () => {
  const urlEl = document.getElementById('url');
  const statusEl = document.getElementById('status');
  const scoreEl = document.getElementById('score');

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0] || !tabs[0].url) {
      urlEl.innerText = "Cannot scan this page";
      statusEl.innerText = "N/A";
      return;
    }

    const currentUrl = tabs[0].url;
    urlEl.innerText = currentUrl;

    if (!currentUrl.startsWith('http')) {
      statusEl.className = 'status-box status-safe';
      statusEl.innerText = 'INTERNAL PAGE';
      scoreEl.innerText = 'Risk Score: 0%';
      return;
    }

    fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: currentUrl })
    })
    .then(res => res.json())
    .then(data => {
      if (data.is_phishing) {
        statusEl.className = 'status-box status-danger';
        statusEl.innerText = '⚠️ HIGH RISK PHISHING';
      } else {
        statusEl.className = 'status-box status-safe';
        statusEl.innerText = '✅ SAFE WEBSITE';
      }
      scoreEl.innerText = `Risk Score: ${data.risk_score}%`;
    })
    .catch(err => {
      statusEl.className = 'status-box status-danger';
      statusEl.innerText = 'SERVER ERROR';
      scoreEl.innerText = 'Cannot connect to backend';
    });
  });
});