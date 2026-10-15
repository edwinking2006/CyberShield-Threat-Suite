const BACKEND_URL = "https://cybershield-threat-suite.onrender.com/scan-url";

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only run on fully loaded HTTP/HTTPS webpages
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        fetch(BACKEND_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: tab.url })
        })
        .then(response => response.json())
        .then(data => {
            if (data.is_phishing) {
                // Safe tab messaging with error catching
                chrome.tabs.sendMessage(tabId, { action: "SHOW_WARNING", result: data }, (response) => {
                    if (chrome.runtime.lastError) {
                        // Ignore harmless tab-not-ready errors
                    }
                });
            }
        })
        .catch(err => console.error("API Error:", err));
    }
});