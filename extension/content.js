/**
 * AegisSOC Edge Interceptor — Isolated Content Script & Closed Shadow DOM HUD (content.js)
 * Intercepts WhatsApp Web & Gmail attachments, verifies magic bytes, coordinates
 * cloud triage with background.js, and renders a tamper-proof Shadow DOM console.
 */
(function () {
  const CONSOLE_URL = "https://threat-detection-ui.vercel.app";

  // 1. Build Closed Shadow DOM HUD so page scripts cannot tamper with security alerts
  const hostEl = document.createElement("div");
  hostEl.id = "aegissoc-shadow-host";
  hostEl.style.cssText = "all: initial; position: fixed; z-index: 2147483647; bottom: 20px; right: 20px; font-family: Inter, system-ui, sans-serif;";
  document.documentElement.appendChild(hostEl);

  const shadow = hostEl.attachShadow({ mode: "closed" });

  shadow.innerHTML = `
    <style>
      * { box-sizing: border-box; font-family: 'Inter', -apple-system, BlinkMacSystemFont, monospace, sans-serif; }
      .aegis-pill {
        display: flex; align-items: center; gap: 8px;
        background: rgba(6, 11, 24, 0.92); color: #f1f5f9;
        border: 1px solid rgba(56, 189, 248, 0.45);
        padding: 8px 14px; border-radius: 999px;
        font-size: 12px; font-weight: 600; cursor: pointer;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.65), 0 0 15px rgba(56, 189, 248, 0.2);
        backdrop-filter: blur(12px); transition: all 0.25s ease;
      }
      .aegis-pill:hover { border-color: #38bdf8; transform: translateY(-2px); }
      .pulse-dot {
        width: 8px; height: 8px; border-radius: 50%;
        background: #10b981; box-shadow: 0 0 8px #10b981;
      }
      .aegis-card {
        display: none; width: 360px;
        background: rgba(10, 16, 31, 0.96); color: #f1f5f9;
        border: 1px solid rgba(56, 189, 248, 0.4);
        border-radius: 16px; padding: 16px; margin-bottom: 10px;
        box-shadow: 0 20px 50px rgba(0, 0, 0, 0.85), 0 0 25px rgba(56, 189, 248, 0.15);
        backdrop-filter: blur(16px);
      }
      .aegis-card.active { display: block; }
      .aegis-card.threat { border-color: rgba(244, 63, 94, 0.8); box-shadow: 0 20px 50px rgba(0,0,0,0.9), 0 0 30px rgba(244, 63, 94, 0.35); }
      .aegis-card.clean { border-color: rgba(16, 185, 129, 0.7); }
      .card-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(51, 65, 85, 0.6); padding-bottom: 10px; margin-bottom: 12px; }
      .card-title { font-size: 13px; font-weight: 700; color: #ffffff; display: flex; align-items: center; gap: 6px; }
      .close-btn { background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 15px; font-weight: bold; }
      .close-btn:hover { color: #ffffff; }
      .meta-row { font-size: 11px; color: #94a3b8; margin-bottom: 6px; word-break: break-all; font-family: monospace; }
      .verdict-banner {
        padding: 10px 12px; border-radius: 10px; font-size: 12px; font-weight: 700;
        margin: 10px 0; display: flex; justify-content: space-between; align-items: center;
      }
      .verdict-scanning { background: rgba(56, 189, 248, 0.12); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
      .verdict-threat { background: rgba(244, 63, 94, 0.18); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.45); }
      .verdict-clean { background: rgba(16, 185, 129, 0.16); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
      .summary-box { font-size: 11.5px; line-height: 1.45; color: #cbd5e1; background: rgba(2, 6, 23, 0.65); padding: 10px; border-radius: 8px; border: 1px solid rgba(30, 41, 59, 0.8); margin-bottom: 10px; }
      .btn-row { display: flex; gap: 8px; margin-top: 10px; }
      .btn {
        flex: 1; padding: 8px 10px; border-radius: 8px; font-size: 11px; font-weight: 600;
        text-align: center; cursor: pointer; border: none; text-decoration: none;
        transition: opacity 0.2s;
      }
      .btn:hover { opacity: 0.9; }
      .btn-primary { background: #38bdf8; color: #030712; }
      .btn-danger { background: #f43f5e; color: #ffffff; }
      .btn-outline { background: rgba(30, 41, 59, 0.8); color: #e2e8f0; border: 1px solid rgba(71, 85, 105, 0.7); }
      .drop-test-zone {
        margin-top: 8px; padding: 10px; border: 1px dashed rgba(56, 189, 248, 0.4);
        border-radius: 8px; text-align: center; font-size: 11px; color: #94a3b8; cursor: pointer;
      }
      .drop-test-zone:hover { border-color: #38bdf8; color: #e2e8f0; background: rgba(56, 189, 248, 0.05); }
    </style>

    <div class="aegis-card" id="aegisCard">
      <div class="card-header">
        <div class="card-title">🛡️ AegisSOC Edge Interceptor</div>
        <button class="close-btn" id="closeCardBtn">✕</button>
      </div>
      <div class="meta-row" id="fileMetaRow">Monitoring WhatsApp Web & Gmail streams...</div>
      <div class="verdict-banner verdict-scanning" id="verdictBanner">
        <span id="verdictText">STANDBY // ZERO-TRUST GATE</span>
        <span id="confidenceText">24/7 CPU</span>
      </div>
      <div class="summary-box" id="summaryBox">
        Downloads and attachments on this tab are automatically intercepted and verified via ResNet-50 Grad-CAM & Shannon Entropy before reaching your disk.
      </div>
      <input type="file" id="manualFileInput" style="display:none" />
      <div class="drop-test-zone" id="manualScanTrigger">
        ⚡ Click or Drop Any Attachment Here to Test Instant Triage
      </div>
      <div class="btn-row">
        <a class="btn btn-primary" href="${CONSOLE_URL}" target="_blank" rel="noopener noreferrer">Open Executive Console</a>
      </div>
    </div>

    <div class="aegis-pill" id="aegisPill">
      <span class="pulse-dot" id="pillDot"></span>
      <span id="pillLabel">AegisSOC Shield Active</span>
    </div>
  `;

  const cardEl = shadow.getElementById("aegisCard");
  const pillEl = shadow.getElementById("aegisPill");
  const pillDot = shadow.getElementById("pillDot");
  const pillLabel = shadow.getElementById("pillLabel");
  const closeCardBtn = shadow.getElementById("closeCardBtn");
  const fileMetaRow = shadow.getElementById("fileMetaRow");
  const verdictBanner = shadow.getElementById("verdictBanner");
  const verdictText = shadow.getElementById("verdictText");
  const confidenceText = shadow.getElementById("confidenceText");
  const summaryBox = shadow.getElementById("summaryBox");
  const manualScanTrigger = shadow.getElementById("manualScanTrigger");
  const manualFileInput = shadow.getElementById("manualFileInput");

  pillEl.addEventListener("click", () => cardEl.classList.toggle("active"));
  closeCardBtn.addEventListener("click", () => cardEl.classList.remove("active"));
  manualScanTrigger.addEventListener("click", () => manualFileInput.click());

  manualFileInput.addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onloadend = () => {
      const res = String(reader.result || "");
      const base64Data = res.includes(",") ? res.split(",")[1] : res;
      processInterceptedPayload({
        blobUrl: null,
        filename: file.name,
        mimeType: file.type || "application/octet-stream",
        originalSize: file.size,
        magicHex: "MANUAL_INSPECTION",
        base64Data: base64Data
      });
    };
    reader.readAsDataURL(file);
  });

  function showScanningUI(filename, sizeBytes, magicHex) {
    cardEl.className = "aegis-card active";
    pillDot.style.background = "#38bdf8";
    pillLabel.textContent = "Scanning Attachment...";
    const kb = sizeBytes ? (sizeBytes / 1024).toFixed(1) + " KB" : "Stream";
    fileMetaRow.textContent = `Target: ${filename} (${kb}) • Header: [${magicHex || "AUTO"}]`;
    verdictBanner.className = "verdict-banner verdict-scanning";
    verdictText.textContent = "⏳ NEURAL TRIAGE IN PROGRESS...";
    confidenceText.textContent = "Hold Gate";
    summaryBox.textContent = "Holding browser download gate while computing 2D Nataraj byte matrix, ResNet-50 activations, and LSB steganography entropy...";
  }

  function renderVerdictUI(filename, data, blobUrl) {
    const risk = String(data.risk_level || "LOW").toUpperCase();
    const verdict = String(data.verdict || "BENIGN").toUpperCase();
    const isThreat = risk === "CRITICAL" || risk === "HIGH" || verdict.includes("MALICIOUS") || verdict.includes("SUSPICIOUS");
    const conf = data.confidence !== null && data.confidence !== undefined ? Math.round(data.confidence) : (isThreat ? 98 : 5);
    const ai = data.ai_analysis || {};

    if (isThreat) {
      cardEl.className = "aegis-card active threat";
      pillDot.style.background = "#f43f5e";
      pillDot.style.boxShadow = "0 0 10px #f43f5e";
      pillLabel.textContent = `🚨 Threat Blocked: ${filename}`;
      verdictBanner.className = "verdict-banner verdict-threat";
      verdictText.textContent = `🚨 BLOCKED: ${verdict}`;
      confidenceText.textContent = `${conf}% Risk`;
      summaryBox.textContent = `${ai.executive_summary || "Malicious spatial byte signature or stego payload detected."} Action: Download terminated & blob revoked.`;

      if (blobUrl) {
        window.dispatchEvent(new CustomEvent("AEGIS_BLOB_VERDICT", {
          detail: { blobUrl, filename, action: "BLOCK" }
        }));
      }
    } else {
      cardEl.className = "aegis-card active clean";
      pillDot.style.background = "#10b981";
      pillDot.style.boxShadow = "0 0 8px #10b981";
      pillLabel.textContent = `✅ Verified Clean: ${filename}`;
      verdictBanner.className = "verdict-banner verdict-clean";
      verdictText.textContent = `✅ ${verdict}`;
      confidenceText.textContent = `${conf}% Risk`;
      summaryBox.textContent = `${ai.executive_summary || "Zero-execution inspection passed with clean byte structure."} Action: Download released safely.`;

      if (blobUrl) {
        window.dispatchEvent(new CustomEvent("AEGIS_BLOB_VERDICT", {
          detail: { blobUrl, filename, action: "ALLOW" }
        }));
      }
    }
  }

  function processInterceptedPayload(payload) {
    const { blobUrl, filename, mimeType, originalSize, magicHex, base64Data, sourceUrl } = payload;
    showScanningUI(filename, originalSize, magicHex);

    chrome.runtime.sendMessage(
      {
        type: "AEGIS_ANALYZE_FILE",
        filename,
        mimeType,
        base64Data,
        sourceUrl
      },
      (response) => {
        if (chrome.runtime.lastError || !response || response.error) {
          const errMsg = (response && response.error) || (chrome.runtime.lastError && chrome.runtime.lastError.message) || "Backend unreachable";
          verdictBanner.className = "verdict-banner verdict-threat";
          verdictText.textContent = "⚠️ TRIAGE ERROR";
          confidenceText.textContent = "Held";
          summaryBox.textContent = `Could not verify file safety (${errMsg}). Check Executive Console.`;
          return;
        }
        renderVerdictUI(filename, response.data, blobUrl);
      }
    );
  }

  // 2. Listen for WhatsApp Web decrypted Blob downloads from injector.js
  window.addEventListener("AEGIS_INTERCEPTED_BLOB", (event) => {
    if (event.detail) {
      processInterceptedPayload(event.detail);
    }
  });

  // 3. Capture-phase click interceptor for Gmail attachment download links
  const approvedGmailUrls = new Set();
  document.addEventListener("click", (e) => {
    if (location.hostname !== "mail.google.com") return;
    const anchor = e.target.closest("a[href*='view=att'], a[href*='googleusercontent.com'], a[download]");
    if (!anchor || !anchor.href) return;
    if (approvedGmailUrls.has(anchor.href)) return;

    e.preventDefault();
    e.stopPropagation();

    const filename = anchor.getAttribute("download") || anchor.innerText.trim() || "gmail_attachment.bin";
    showScanningUI(filename, 0, "GMAIL_STREAM");

    chrome.runtime.sendMessage(
      {
        type: "AEGIS_ANALYZE_URL",
        url: anchor.href,
        filename: filename
      },
      (response) => {
        if (!response || response.error) {
          verdictBanner.className = "verdict-banner verdict-threat";
          verdictText.textContent = "⚠️ SCAN ERROR";
          summaryBox.textContent = (response && response.error) || "Failed to scan Gmail attachment stream.";
          return;
        }
        renderVerdictUI(filename, response.data, null);
        const risk = String(response.data.risk_level || "LOW").toUpperCase();
        const verdict = String(response.data.verdict || "BENIGN").toUpperCase();
        const isThreat = risk === "CRITICAL" || risk === "HIGH" || verdict.includes("MALICIOUS") || verdict.includes("SUSPICIOUS");
        if (!isThreat) {
          approvedGmailUrls.add(anchor.href);
          anchor.click();
        }
      }
    );
  }, true);
})();
