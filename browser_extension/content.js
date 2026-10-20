chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "WARN_USER") {
    // Prevent duplicate banners
    if (document.getElementById('cybershield-warning-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'cybershield-warning-banner';
    banner.style.position = 'fixed';
    banner.style.top = '0';
    banner.style.left = '0';
    banner.style.width = '100%';
    banner.style.backgroundColor = '#ff2222';
    banner.style.color = '#ffffff';
    banner.style.padding = '14px 20px';
    banner.style.textAlign = 'center';
    banner.style.zIndex = '999999999';
    banner.style.fontWeight = 'bold';
    banner.style.fontSize = '15px';
    banner.style.fontFamily = 'Segoe UI, Tahoma, sans-serif';
    banner.style.boxShadow = '0px 4px 15px rgba(0,0,0,0.5)';
    banner.style.borderBottom = '3px solid #990000';
    
    banner.innerHTML = `🚨 CYBERSECURITY WARNING: CyberShield has flagged this active webpage as a Phishing Threat! (Risk Score: ${request.risk}% | Status: ${request.status})`;
    
    // Inject at the very top of body
    if (document.body) {
      document.body.prepend(banner);
    } else {
      document.documentElement.prepend(banner);
    }
  }
});