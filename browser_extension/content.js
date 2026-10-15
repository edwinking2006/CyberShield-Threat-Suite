chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "SHOW_ALERT") {
    const data = request.data;
    if (data.is_phishing) {
      const banner = document.createElement('div');
      banner.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100%; z-index: 999999;
        background: #ff0055; color: #fff; text-align: center;
        padding: 12px; font-weight: bold; font-family: sans-serif;
        box-shadow: 0 4px 15px rgba(255,0,85,0.5);
      `;
      banner.innerHTML = `⚠️ CYBERSHIELD WARNING: High Risk Phishing Site Detected! (Risk: ${data.risk_score}%)`;
      document.body.prepend(banner);
    }
  }
});