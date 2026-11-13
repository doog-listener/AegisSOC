/**
 * AegisSOC Edge Interceptor — Service Worker (background.js)
 * Coordinates SHA-256 verdict caching, FastAPI cloud communication,
 * and OS-level chrome.downloads quarantine enforcement.
 */
const API_BASE = "https://teem5002-aegissoc-backend.hf.space";
const verdictCache = new Map();

// Convert Base64 string to Uint8Array
function base64ToUint8Array(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// Compute SHA-256 hex digest for 0ms deduplication
async function sha256Hex(uint8Array) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", uint8Array);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// Send binary buffer to Hugging Face FastAPI /api/analyze
async function analyzeBufferWithBackend(uint8Array, filename, mimeType) {
  const fileHash = await sha256Hex(uint8Array);
  if (verdictCache.has(fileHash)) {
    return verdictCache.get(fileHash);
  }

  const blob = new Blob([uint8Array], { type: mimeType || "application/octet-stream" });
  const formData = new FormData();
  formData.append("file", blob, filename || "intercepted_target.bin");
  formData.append("analysis_mode", "auto");

  const response = await fetch(`${API_BASE}/api/analyze`, {
    method: "POST",
    body: formData
  });

  if (!response.ok) {
    const errBody = await response.json().catch(() => ({}));
    throw new Error(errBody.detail || `Backend returned HTTP ${response.status}`);
  }

  const result = await response.json();
  verdictCache.set(fileHash, result);
  return result;
}

// 1. Handle IPC requests from content.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "AEGIS_ANALYZE_FILE") {
    (async () => {
      try {
        const bytes = base64ToUint8Array(message.base64Data);
        const data = await analyzeBufferWithBackend(bytes, message.filename, message.mimeType);
        sendResponse({ data });
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true; // Keep async message channel open
  }

  if (message.type === "AEGIS_ANALYZE_URL") {
    (async () => {
      try {
        const res = await fetch(message.url, { credentials: "include" });
        if (!res.ok) throw new Error(`Attachment fetch HTTP ${res.status}`);
        const arrayBuffer = await res.arrayBuffer();
        const bytes = new Uint8Array(arrayBuffer);
        const contentType = res.headers.get("content-type") || "application/octet-stream";
        const data = await analyzeBufferWithBackend(bytes, message.filename, contentType);
        sendResponse({ data });
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }
});

// 2. Defense-in-Depth: OS-Level Download Quarantine Backstop
const HIGH_RISK_EXTENSIONS = [".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".hta"];

chrome.downloads.onDeterminingFilename.addListener((downloadItem) => {
  const url = (downloadItem.finalUrl || downloadItem.url || "").toLowerCase();
  const ref = (downloadItem.referrer || "").toLowerCase();
  const fname = (downloadItem.filename || "").toLowerCase();

  const isMonitoredOrigin =
    url.includes("whatsapp.com") ||
    url.includes("google.com") ||
    url.includes("googleusercontent.com") ||
    ref.includes("whatsapp.com") ||
    ref.includes("mail.google.com");

  if (!isMonitoredOrigin) return;

  const isHighRiskExec = HIGH_RISK_EXTENSIONS.some(ext => fname.endsWith(ext));
  if (isHighRiskExec && !url.startsWith("blob:")) {
    // Pause direct unverified executable streams and inspect
    chrome.downloads.pause(downloadItem.id, () => {
      fetch(downloadItem.finalUrl || downloadItem.url, { credentials: "include" })
        .then(r => r.arrayBuffer())
        .then(buf => analyzeBufferWithBackend(new Uint8Array(buf), downloadItem.filename, downloadItem.mime))
        .then(verdictData => {
          const risk = String(verdictData.risk_level || "LOW").toUpperCase();
          const v = String(verdictData.verdict || "BENIGN").toUpperCase();
          if (risk === "CRITICAL" || risk === "HIGH" || v.includes("MALICIOUS")) {
            chrome.downloads.cancel(downloadItem.id);
            chrome.downloads.erase({ id: downloadItem.id });
          } else {
            chrome.downloads.resume(downloadItem.id);
          }
        })
        .catch(() => {
          // Resume if stream cannot be fetched by service worker
          chrome.downloads.resume(downloadItem.id);
        });
    });
  }
});
