chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
      fetch('https://cybershield-threat-suite.onrender.com/scan-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url })
      })
      .then(res => res.json())
      .then(data => {
        if (data.is_phishing || data.risk_score >= 50) {
          // Send message to content.js to inject banner
          chrome.tabs.sendMessage(tabId, {
            action: "WARN_USER",
            risk: data.risk_score,
            status: data.status
          }).catch(err => console.log("Content script not ready yet:", err));
        }
      })
      .catch(err => console.error("Background scan error:", err));
    }
  }
});