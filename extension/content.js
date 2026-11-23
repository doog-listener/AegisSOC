/**
 * AegisSOC Edge Interceptor v2.6 — Isolated Content Script & Closed Shadow DOM HUD (content.js)
 * Fixes all 3 reported issues:
 * 1. Direct Download (No New Tab): Downloads inside Gmail's Preview Modal or attachment cards save
 *    directly via verified Blob anchors instead of opening a new browser tab.
 * 2. Full PDF Support: Scans PDFs (magic bytes, embedded executables, /JavaScript, /OpenAction, /Launch,
 *    /EmbeddedFile, /RichMedia, entropy) so clean PDFs pass and malicious PDFs are blocked.
 * 3. Zero Duplicate Scans: Caches verified verdicts + blobs by attachment ID, normalized URL, and filename.
 *    If an attachment was already scanned when opened/previewed, clicking Download saves it in 0ms!
 */
(function () {
  const CONSOLE_URL = "https://aegissoc.vercel.app";

  // Notify AegisSOC Executive Console when visited so the website shows "Shield Active"
  if (location.hostname === "aegissoc.vercel.app" || location.hostname === "threat-detection-ui.vercel.app") {
    document.documentElement.dataset.aegissocInstalled = "2.6.1";
    window.dispatchEvent(new CustomEvent("AEGISSOC_EXTENSION_READY", { detail: { version: "2.6.1" } }));
    return;
  }

  // In-memory session cache for instant 0ms reuse between Preview -> Download
  // Key -> { isClean, verdictData, base64Data, mimeType, filename, gmailUrl }
  const sessionAttachmentCache = new Map();
  let lastPreviewedAttachment = null;

  function normalizeAttachmentKey(rawUrl, filename = "") {
    try {
      const u = new URL(rawUrl, location.origin);
      const attid = u.searchParams.get("attid") || "";
      const permmsgid = u.searchParams.get("permmsgid") || u.searchParams.get("th") || "";
      const realattid = u.searchParams.get("realattid") || "";
      if (permmsgid || attid || realattid) {
        return `gmail:${permmsgid}:${attid}:${realattid}:${filename.toLowerCase()}`;
      }
      u.searchParams.delete("disp");
      u.searchParams.delete("zw");
      u.searchParams.delete("s");
      return `url:${u.toString()}`;
    } catch (e) {
      return `raw:${rawUrl}:${filename}`;
    }
  }

  // 1. Build Closed Shadow DOM HUD
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
        background: rgba(6, 11, 24, 0.94); color: #f1f5f9;
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
        display: none; width: 375px;
        background: rgba(10, 16, 31, 0.97); color: #f1f5f9;
        border: 1px solid rgba(56, 189, 248, 0.4);
        border-radius: 16px; padding: 16px; margin-bottom: 10px;
        box-shadow: 0 20px 50px rgba(0, 0, 0, 0.85), 0 0 25px rgba(56, 189, 248, 0.15);
        backdrop-filter: blur(16px);
      }
      .aegis-card.active { display: block; }
      .aegis-card.threat { border-color: rgba(244, 63, 94, 0.85); box-shadow: 0 20px 50px rgba(0,0,0,0.9), 0 0 30px rgba(244, 63, 94, 0.35); }
      .aegis-card.clean { border-color: rgba(16, 185, 129, 0.75); }
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
      .drop-test-zone {
        margin-top: 8px; padding: 10px; border: 1px dashed rgba(56, 189, 248, 0.4);
        border-radius: 8px; text-align: center; font-size: 11px; color: #94a3b8; cursor: pointer;
      }
      .drop-test-zone:hover { border-color: #38bdf8; color: #e2e8f0; background: rgba(56, 189, 248, 0.05); }
    </style>

    <div class="aegis-card" id="aegisCard">
      <div class="card-header">
        <div class="card-title">🛡️ AegisSOC Edge Interceptor v2.6</div>
        <button class="close-btn" id="closeCardBtn">✕</button>
      </div>
      <div class="meta-row" id="fileMetaRow">Monitoring WhatsApp Web & Gmail attachments...</div>
      <div class="verdict-banner verdict-scanning" id="verdictBanner">
        <span id="verdictText">STANDBY // ZERO-TRUST GATE</span>
        <span id="confidenceText">PE • PDF • Media</span>
      </div>
      <div class="summary-box" id="summaryBox">
        Binaries (.exe/.dll), PDFs (.pdf), and Raster Media (.png/.jpg) are inspected once and cached for instant, direct downloads.
      </div>
      <input type="file" id="manualFileInput" style="display:none" />
      <div class="drop-test-zone" id="manualScanTrigger">
        ⚡ Click Here to Test Manual File Triage
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

  manualFileInput.addEventListener("change", (e) => {
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

  function showScanningUI(filename, sizeBytes, magicHex, actionLabel = "Hold Gate") {
    cardEl.className = "aegis-card active";
    pillDot.style.background = "#38bdf8";
    pillLabel.textContent = `Scanning: ${filename}`;
    const kb = sizeBytes ? (sizeBytes / 1024).toFixed(1) + " KB" : "Attachment Stream";
    fileMetaRow.textContent = `Target: ${filename} (${kb}) • Source: [${magicHex || "AUTO"}]`;
    verdictBanner.className = "verdict-banner verdict-scanning";
    verdictText.textContent = "⏳ NEURAL & STRUCTURAL TRIAGE...";
    confidenceText.textContent = actionLabel;
    summaryBox.textContent = "Inspecting PE binary matrix, PDF active triggers (/JavaScript, /OpenAction, /Launch, /EmbeddedFile), and steganography entropy...";
  }

  function isThreatVerdict(data) {
    const risk = String(data.risk_level || "LOW").toUpperCase();
    const verdict = String(data.verdict || "BENIGN").toUpperCase();
    return risk === "CRITICAL" || risk === "HIGH" || verdict.includes("MALICIOUS") || verdict.includes("SUSPICIOUS");
  }

  function renderVerdictUI(filename, data, options = {}) {
    const {
      blobUrl,
      gmailUrl,
      base64Data,
      mimeType,
      triggerDownload = true,
      actionContext = "Download",
      fromCache = false
    } = options;

    const verdict = String(data.verdict || "BENIGN").toUpperCase();
    const isThreat = isThreatVerdict(data);
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
      summaryBox.textContent = `${ai.executive_summary || "Malicious payload or active exploit trigger detected."} Action: ${actionContext} blocked & quarantined.`;

      if (blobUrl || gmailUrl) {
        window.dispatchEvent(new CustomEvent("AEGIS_BLOB_VERDICT", {
          detail: { blobUrl, gmailUrl, filename, action: "BLOCK" }
        }));
      }
    } else {
      cardEl.className = "aegis-card active clean";
      pillDot.style.background = "#10b981";
      pillDot.style.boxShadow = "0 0 8px #10b981";
      pillLabel.textContent = `✅ Verified Clean: ${filename}`;
      verdictBanner.className = "verdict-banner verdict-clean";
      verdictText.textContent = fromCache ? `⚡ CACHED VERIFIED CLEAN` : `✅ ${verdict}`;
      confidenceText.textContent = fromCache ? "0ms Reuse" : `${conf}% Risk`;
      summaryBox.textContent = fromCache
        ? `Already verified clean during preview. Releasing "${filename}" directly to your Downloads folder without re-scanning.`
        : `${ai.executive_summary || "Inspection passed with clean structural and neural signatures."} Action: ${actionContext} released directly.`;

      window.dispatchEvent(new CustomEvent("AEGIS_BLOB_VERDICT", {
        detail: {
          blobUrl,
          gmailUrl,
          filename,
          base64Data,
          mimeType,
          triggerDownload: !!triggerDownload,
          action: "ALLOW"
        }
      }));
    }
    return !isThreat;
  }

  function processInterceptedPayload(payload) {
    const { blobUrl, filename, mimeType, originalSize, magicHex, base64Data } = payload;
    showScanningUI(filename, originalSize, magicHex);

    chrome.runtime.sendMessage(
      {
        type: "AEGIS_ANALYZE_FILE",
        filename,
        mimeType,
        base64Data
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
        renderVerdictUI(filename, response.data, { blobUrl, base64Data, mimeType, triggerDownload: true });
      }
    );
  }

  // 2. Listen for WhatsApp Web decrypted Blob downloads from injector.js
  window.addEventListener("AEGIS_INTERCEPTED_BLOB", (event) => {
    if (event.detail) {
      processInterceptedPayload(event.detail);
    }
  });

  // 3. Listen for Gmail hidden-iframe / window.open / anchor downloads from injector.js
  window.addEventListener("AEGIS_INTERCEPTED_GMAIL_URL", (event) => {
    const { url, filename } = event.detail || {};
    if (!url) return;

    // Check if this URL or the currently previewed attachment was ALREADY scanned & verified!
    const key = normalizeAttachmentKey(url, filename);
    const cached = sessionAttachmentCache.get(key) ||
      (lastPreviewedAttachment && (url.includes("googleusercontent.com") || url.includes("view=att")) ? lastPreviewedAttachment : null);

    if (cached) {
      renderVerdictUI(cached.filename || filename, cached.verdictData, {
        gmailUrl: url,
        base64Data: cached.base64Data,
        mimeType: cached.mimeType,
        triggerDownload: cached.isClean,
        actionContext: "Download",
        fromCache: true
      });
      return;
    }

    scanGmailUrlAndAct(url, filename || "gmail_attachment", {
      triggerDownload: true,
      actionContext: "Download"
    });
  });

  // 4. Listen for background.js notifications if chrome.downloads catches a direct stream
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "AEGIS_BG_SCAN_START") {
      showScanningUI(message.filename, message.sizeBytes || 0, "BROWSER_DOWNLOAD_GATE");
    } else if (message.type === "AEGIS_BG_SCAN_RESULT") {
      renderVerdictUI(message.filename, message.data, {
        base64Data: message.base64Data,
        mimeType: message.mimeType,
        triggerDownload: !isThreatVerdict(message.data),
        actionContext: "Download"
      });
    } else if (message.type === "AEGIS_BG_SCAN_ERROR") {
      cardEl.className = "aegis-card active threat";
      verdictBanner.className = "verdict-banner verdict-threat";
      verdictText.textContent = "🚨 UNVERIFIED DOWNLOAD HELD";
      summaryBox.textContent = `Download aborted because scan failed: ${message.error}`;
    }
  });

  // =========================================================================
  // 5. GMAIL ATTACHMENT CARD & PREVIEW LIGHTBOX INTERCEPTOR
  // =========================================================================
  function parseGmailDownloadUrlAttr(raw) {
    if (!raw) return null;
    const httpIdx = raw.indexOf(":http");
    if (httpIdx === -1) return null;
    const url = raw.substring(httpIdx + 1);
    const prefix = raw.substring(0, httpIdx);
    const firstColon = prefix.indexOf(":");
    if (firstColon === -1) {
      return { mimeType: "application/octet-stream", filename: prefix || "gmail_attachment", url };
    }
    return {
      mimeType: prefix.substring(0, firstColon) || "application/octet-stream",
      filename: prefix.substring(firstColon + 1) || "gmail_attachment",
      url
    };
  }

  function paintGmailCardBadge(cardNode, state, labelText) {
    let badge = cardNode.querySelector(".aegis-inline-badge");
    if (!badge) {
      badge = document.createElement("div");
      badge.className = "aegis-inline-badge";
      badge.style.cssText = "position:absolute; top:4px; left:4px; z-index:999; padding:2px 7px; border-radius:6px; font-size:10px; font-weight:700; font-family:monospace; pointer-events:none; box-shadow:0 2px 8px rgba(0,0,0,0.4);";
      if (getComputedStyle(cardNode).position === "static") {
        cardNode.style.position = "relative";
      }
      cardNode.appendChild(badge);
    }
    if (state === "SCANNING") {
      badge.style.background = "rgba(3, 7, 18, 0.92)";
      badge.style.color = "#38bdf8";
      badge.style.border = "1px solid #38bdf8";
      badge.textContent = labelText || "⏳ Scanning...";
    } else if (state === "BLOCK") {
      badge.style.background = "rgba(136, 19, 55, 0.96)";
      badge.style.color = "#fda4af";
      badge.style.border = "1px solid #f43f5e";
      badge.textContent = labelText || "🚨 QUARANTINED";
      cardNode.style.outline = "2px solid #f43f5e";
      cardNode.style.filter = "grayscale(60%)";
    } else if (state === "ALLOW") {
      badge.style.background = "rgba(6, 78, 59, 0.95)";
      badge.style.color = "#6ee7b7";
      badge.style.border = "1px solid #10b981";
      badge.textContent = labelText || "✅ VERIFIED CLEAN";
      cardNode.style.outline = "2px solid #10b981";
    } else {
      badge.style.background = "rgba(15, 23, 42, 0.88)";
      badge.style.color = "#38bdf8";
      badge.style.border = "1px solid rgba(56, 189, 248, 0.45)";
      badge.textContent = labelText || "🛡️ AegisSOC Gate";
    }
  }

  function scanGmailUrlAndAct(url, filename, opts = {}) {
    const { cardNode, clickedTarget, isDownloadButton, triggerDownload } = opts;
    const cacheKey = normalizeAttachmentKey(url, filename);

    // 0ms Instant Cache Check: Never scan the same attachment twice!
    if (sessionAttachmentCache.has(cacheKey)) {
      const cached = sessionAttachmentCache.get(cacheKey);
      renderVerdictUI(cached.filename || filename, cached.verdictData, {
        gmailUrl: url,
        base64Data: cached.base64Data,
        mimeType: cached.mimeType,
        triggerDownload: !!(cached.isClean && (isDownloadButton || triggerDownload)),
        actionContext: isDownloadButton || triggerDownload ? "Download" : "Preview & Open",
        fromCache: true
      });
      if (cached.isClean && !isDownloadButton && clickedTarget) {
        lastPreviewedAttachment = cached;
        setTimeout(() => {
          clickedTarget.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true, view: window }));
          clickedTarget.dispatchEvent(new MouseEvent("mouseup", { bubbles: true, cancelable: true, view: window }));
          clickedTarget.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window }));
        }, 40);
      }
      return;
    }

    const actionLabel = isDownloadButton || triggerDownload ? "Download Gate" : "Preview Gate";
    showScanningUI(filename, 0, "GMAIL_ATTACHMENT", actionLabel);

    if (cardNode) {
      cardNode.dataset.aegisVerdict = "SCANNING";
      paintGmailCardBadge(cardNode, "SCANNING", "⏳ Scanning...");
    }

    chrome.runtime.sendMessage(
      {
        type: "AEGIS_ANALYZE_URL",
        url: url,
        filename: filename
      },
      (response) => {
        if (chrome.runtime.lastError || !response || response.error) {
          const errMsg = (response && response.error) || (chrome.runtime.lastError && chrome.runtime.lastError.message) || "Scan failed";
          if (cardNode) {
            delete cardNode.dataset.aegisVerdict;
            paintGmailCardBadge(cardNode, "BLOCK", "⚠️ Scan Error");
          }
          verdictBanner.className = "verdict-banner verdict-threat";
          verdictText.textContent = "⚠️ SCAN ERROR";
          confidenceText.textContent = "Blocked";
          summaryBox.textContent = `Attachment held because verification failed: ${errMsg}`;
          return;
        }

        const isClean = renderVerdictUI(filename, response.data, {
          gmailUrl: url,
          base64Data: response.base64Data,
          mimeType: response.mimeType,
          triggerDownload: !!(isDownloadButton || triggerDownload),
          actionContext: isDownloadButton || triggerDownload ? "Download" : "Preview & Open"
        });

        const cacheEntry = {
          isClean,
          verdictData: response.data,
          base64Data: response.base64Data,
          mimeType: response.mimeType,
          filename,
          gmailUrl: url
        };
        sessionAttachmentCache.set(cacheKey, cacheEntry);
        if (isClean && !isDownloadButton) {
          lastPreviewedAttachment = cacheEntry;
        }

        if (cardNode) {
          if (isClean) {
            cardNode.dataset.aegisVerdict = "ALLOW";
            paintGmailCardBadge(cardNode, "ALLOW", "✅ VERIFIED CLEAN");
            if (!isDownloadButton && clickedTarget) {
              setTimeout(() => {
                clickedTarget.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true, view: window }));
                clickedTarget.dispatchEvent(new MouseEvent("mouseup", { bubbles: true, cancelable: true, view: window }));
                clickedTarget.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window }));
              }, 80);
            }
          } else {
            cardNode.dataset.aegisVerdict = "BLOCK";
            paintGmailCardBadge(cardNode, "BLOCK", "🚨 MALICIOUS // BLOCKED");
          }
        }
      }
    );
  }

  if (location.hostname === "mail.google.com") {
    const observer = new MutationObserver(() => {
      document.querySelectorAll("[download_url]").forEach((card) => {
        if (!card.dataset.aegisHooked) {
          card.dataset.aegisHooked = "1";
          const parsed = parseGmailDownloadUrlAttr(card.getAttribute("download_url"));
          if (parsed && parsed.url) {
            const key = normalizeAttachmentKey(parsed.url, parsed.filename);
            if (sessionAttachmentCache.has(key)) {
              const cached = sessionAttachmentCache.get(key);
              card.dataset.aegisVerdict = cached.isClean ? "ALLOW" : "BLOCK";
              paintGmailCardBadge(card, cached.isClean ? "ALLOW" : "BLOCK", cached.isClean ? "✅ VERIFIED CLEAN" : "🚨 MALICIOUS // BLOCKED");
              return;
            }
          }
          paintGmailCardBadge(card, "STANDBY", "🛡️ AegisSOC Gate");
        }
      });
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    const interceptGmailEvent = (e) => {
      if (!e.isTrusted) return;

      // Case 1: User is inside Gmail's Preview Modal (div[role="dialog"]) and clicks the Download button!
      const dialogNode = e.target.closest("div[role='dialog']");
      if (dialogNode && lastPreviewedAttachment) {
        const dlBtn = e.target.closest(
          "[data-tooltip*='Download'], [aria-label*='Download'], [data-tooltip*='download'], [aria-label*='download']"
        );
        if (dlBtn) {
          e.preventDefault();
          e.stopPropagation();
          e.stopImmediatePropagation();

          if (e.type === "click" || e.type === "mousedown") {
            // Trigger immediate direct blob download (NO new tab, NO re-scan!)
            renderVerdictUI(lastPreviewedAttachment.filename, lastPreviewedAttachment.verdictData, {
              gmailUrl: lastPreviewedAttachment.gmailUrl,
              base64Data: lastPreviewedAttachment.base64Data,
              mimeType: lastPreviewedAttachment.mimeType,
              triggerDownload: lastPreviewedAttachment.isClean,
              actionContext: "Download",
              fromCache: true
            });
          }
          return;
        }
      }

      // Case 2: User clicks an attachment card in the email thread
      const cardNode = e.target.closest("[download_url]");
      if (cardNode) {
        const verdictState = cardNode.dataset.aegisVerdict;
        const parsed = parseGmailDownloadUrlAttr(cardNode.getAttribute("download_url"));
        const isDownloadButton = !!e.target.closest(
          "[data-tooltip*='Download'], [aria-label*='Download'], [data-tooltip*='download'], [aria-label*='download'], .aSK, .aQv, a[download]"
        );

        // Already verified clean:
        if (verdictState === "ALLOW") {
          // If clicking Download on an already-verified card, save directly via cached Blob (0ms, no re-scan, no new tab)
          if (isDownloadButton && parsed && parsed.url) {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            if (e.type === "click" || e.type === "mousedown") {
              scanGmailUrlAndAct(parsed.url, parsed.filename, {
                cardNode,
                clickedTarget: e.target,
                isDownloadButton: true
              });
            }
          }
          // If clicking the card body to open preview, let Gmail open the already-verified preview!
          if (!isDownloadButton && parsed && parsed.url) {
            const key = normalizeAttachmentKey(parsed.url, parsed.filename);
            if (sessionAttachmentCache.has(key)) {
              lastPreviewedAttachment = sessionAttachmentCache.get(key);
            }
          }
          return;
        }

        // Not yet verified -> block Gmail's default action until scan completes
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();

        if (verdictState === "BLOCK") {
          if (e.type === "click" || e.type === "mousedown") {
            cardEl.className = "aegis-card active threat";
            verdictBanner.className = "verdict-banner verdict-threat";
            verdictText.textContent = "🚨 QUARANTINED ATTACHMENT";
            summaryBox.textContent = "This attachment failed AegisSOC inspection. Opening and downloading are permanently blocked.";
          }
          return;
        }

        if (verdictState === "SCANNING") {
          return;
        }

        if ((e.type === "mousedown" || e.type === "click") && parsed && parsed.url) {
          scanGmailUrlAndAct(parsed.url, parsed.filename, {
            cardNode,
            clickedTarget: e.target,
            isDownloadButton
          });
        }
        return;
      }

      // Case 3: Inline image inside email body (.a3s img)
      const inlineImg = e.target.closest(".a3s img");
      if (inlineImg && inlineImg.src && (inlineImg.naturalWidth > 64 || inlineImg.width > 64)) {
        const imgState = inlineImg.dataset.aegisVerdict;
        if (imgState === "ALLOW") return;

        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();

        if (imgState === "BLOCK" || imgState === "SCANNING") return;

        if (e.type === "mousedown" || e.type === "click") {
          inlineImg.dataset.aegisVerdict = "SCANNING";
          const imgName = inlineImg.getAttribute("alt") || "inline_email_image.png";
          scanGmailUrlAndAct(inlineImg.src, imgName, {
            cardNode: inlineImg.parentElement || inlineImg,
            clickedTarget: inlineImg,
            isDownloadButton: false
          });
        }
      }
    };

    window.addEventListener("mousedown", interceptGmailEvent, true);
    window.addEventListener("mouseup", interceptGmailEvent, true);
    window.addEventListener("click", interceptGmailEvent, true);
  }
})();
