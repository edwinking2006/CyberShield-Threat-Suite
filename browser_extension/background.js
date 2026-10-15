// Render-la host panna app URL-a inga podungha
const BACKEND_URL = "https://your-render-app-name.onrender.com/scan-url";

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    })
    .then(res => res.json())
    .then(data => {
      chrome.tabs.sendMessage(tabId, { action: "SHOW_ALERT", data: data });
    })
    .catch(err => console.error("Scan Error:", err));
  }
});