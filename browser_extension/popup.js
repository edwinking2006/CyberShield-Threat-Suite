document.addEventListener('DOMContentLoaded', () => {
  const urlDisplay = document.getElementById('url-display');
  const statusText = document.getElementById('status-text');
  const scoreText = document.getElementById('score-text');
  const statusCard = document.getElementById('status-card');

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) {
      statusText.innerText = "No Active Tab";
      return;
    }

    const activeTab = tabs[0];
    const currentUrl = activeTab.url || "";

    if (!currentUrl || currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://')) {
      urlDisplay.innerText = currentUrl || "Internal Page";
      statusText.innerHTML = "ℹ️ BROWSER PAGE";
      statusText.style.color = "#94a3b8";
      scoreText.innerText = "Risk Score: 0%";
      return;
    }

    urlDisplay.innerText = currentUrl;
    statusText.innerHTML = "🔄 SCANNING...";

    // Timeout controller so it never hangs indefinitely
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 7000);

    fetch('https://cybershield-threat-suite.onrender.com/scan-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: currentUrl }),
      signal: controller.signal
    })
    .then(res => res.json())
    .then(data => {
      clearTimeout(timeoutId);
      const isDanger = data.is_phishing || data.risk_score >= 50;
      
      if (isDanger) {
        statusText.innerHTML = "🚨 DANGER WEBSITE";
        statusText.style.color = "#ff4444";
        statusCard.style.borderColor = "#ef4444";
        statusCard.style.backgroundColor = "#450a0a";
      } else {
        statusText.innerHTML = "✅ SAFE WEBSITE";
        statusText.style.color = "#22c55e";
        statusCard.style.borderColor = "#22c55e";
        statusCard.style.backgroundColor = "#052e16";
      }

      scoreText.innerHTML = `Risk Score: <b>${data.risk_score}%</b> (${data.status || 'ANALYZED'})`;
    })
    .catch(err => {
      clearTimeout(timeoutId);
      statusText.innerHTML = "⚠️ SCAN ERROR";
      statusText.style.color = "#f59e0b";
      scoreText.innerText = "Server response timeout / offline";
    });
  });
});