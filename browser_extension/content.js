chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "SHOW_WARNING") {
        if (!document.getElementById("cybershield-alert-banner")) {
            const banner = document.createElement("div");
            banner.id = "cybershield-alert-banner";
            banner.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                background-color: #ff0055;
                color: #ffffff;
                padding: 14px;
                text-align: center;
                font-weight: bold;
                font-family: sans-serif;
                font-size: 16px;
                z-index: 999999;
                box-shadow: 0px 4px 15px rgba(255, 0, 85, 0.6);
            `;
            banner.innerHTML = `⚠️ CYBERSHIELD PHISHING ALERT: This site has a high risk score of ${request.result.risk_score}%! Proceed with caution.`;
            document.body.prepend(banner);
        }
    }
    sendResponse({ status: "received" });
    return true;
});