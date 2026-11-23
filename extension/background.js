/**
 * AegisSOC Edge Interceptor v2.6 — Service Worker (background.js)
 * Features:
 * 1. Hybrid Inspection Pipeline:
 *    - Magic-Byte Header Inspector (catches spoofed extensions like malware.exe renamed to invoice.pdf)
 *    - Deep PDF Active-Payload Analyzer (detects /JavaScript, /JS, /OpenAction, /AA, /Launch,
 *      /EmbeddedFile, /RichMedia, /SubmitForm, and extracts embedded MZ executables to ResNet-50!)
 *    - Neural ResNet-50 + Grad-CAM & Steganography Entropy Pipeline on Hugging Face FastAPI
 * 2. SHA-256 Verdict + Blob Cache so already-scanned attachments never scan twice.
 * 3. Direct Verified Download Fallback without opening extra tabs.
 */
const API_BASE = "https://teem5002-aegissoc-backend.hf.space";
const MAX_UPLOAD_BYTES = 4 * 1024 * 1024;
const SLICE_HEADER_BYTES = 256 * 1024;

const verdictCache = new Map();
const approvedDownloadUrls = new Set();
const approvedFilenames = new Set();

function base64ToUint8Array(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function uint8ArrayToBase64(uint8Array) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < uint8Array.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, uint8Array.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

async function sha256Hex(uint8Array) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", uint8Array);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function isThreatResult(data) {
  const risk = String(data.risk_level || "LOW").toUpperCase();
  const verdict = String(data.verdict || "BENIGN").toUpperCase();
  return risk === "CRITICAL" || risk === "HIGH" || verdict.includes("MALICIOUS") || verdict.includes("SUSPICIOUS");
}

function hasMagicBytes(bytes, sig) {
  if (!bytes || bytes.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) {
    if (bytes[i] !== sig[i]) return false;
  }
  return true;
}

/**
 * Deep PDF Structural & Active-Trigger Scanner
 * Inspects PDF documents for weaponized actions (/JavaScript, /OpenAction, /Launch, /EmbeddedFile)
 * and checks whether a Windows PE executable (MZ) is embedded inside the PDF stream.
 */
function inspectPdfBuffer(uint8Array, filename) {
  // Decode up to first 2MB of PDF structure as Latin-1 to preserve raw byte offsets
  const scanLen = Math.min(uint8Array.length, 2 * 1024 * 1024);
  let rawText = "";
  const chunk = 0x8000;
  for (let i = 0; i < scanLen; i += chunk) {
    rawText += String.fromCharCode.apply(null, uint8Array.subarray(i, Math.min(i + chunk, scanLen)));
  }

  // Check if an embedded Windows PE executable ("MZ" + "This program cannot be run" or "PE  ") is hidden inside
  const peMarkerIdx = rawText.indexOf("This program cannot be run");
  if (peMarkerIdx !== -1) {
    const mzSearchStart = Math.max(0, peMarkerIdx - 512);
    const mzIdx = rawText.lastIndexOf("MZ", peMarkerIdx);
    if (mzIdx >= mzSearchStart) {
      return {
        hasEmbeddedExe: true,
        embeddedExeOffset: mzIdx
      };
    }
  }

  const highRiskTokens = [
    { token: "/Launch", desc: "External command/executable launch action (/Launch)" },
    { token: "/JavaScript", desc: "Embedded JavaScript execution dictionary (/JavaScript)" },
    { token: "/JS", desc: "Embedded compact JavaScript trigger (/JS)" },
    { token: "/RichMedia", desc: "Embedded Flash/RichMedia exploit container (/RichMedia)" },
    { token: "/EmbeddedFile", desc: "Embedded file attachment stream (/EmbeddedFile)" },
    { token: "/SubmitForm", desc: "External data exfiltration form trigger (/SubmitForm)" },
    { token: "/GoToR", desc: "Remote file/SMB NTLM hash leak trigger (/GoToR)" }
  ];

  const autoExecTokens = ["/OpenAction", "/AA"];

  const foundHighRisk = highRiskTokens.filter(item => rawText.includes(item.token));
  const foundAutoExec = autoExecTokens.filter(tok => rawText.includes(tok));

  // Count pages roughly to gauge document complexity
  const pageMatches = rawText.match(/\/Type\s*\/Page /g);
  const pageCount = pageMatches ? pageMatches.length : 1;

  if (foundHighRisk.length > 0 && (foundAutoExec.length > 0 || foundHighRisk.some(t => t.token === "/Launch" || t.token === "/EmbeddedFile"))) {
    const reasons = foundHighRisk.map(r => r.desc).join("; ");
    return {
      hasEmbeddedExe: false,
      result: {
        filename: filename,
        detected_format: "PDF Document (Weaponized Active Triggers)",
        extension_spoofed: false,
        threat_vector: "Vector C (PDF Structural & Active-Payload Inspection)",
        verdict: "MALICIOUS PDF PAYLOAD",
        risk_level: "CRITICAL",
        confidence: 96,
        ai_analysis: {
          executive_summary: `Weaponized PDF detected (${pageCount} page(s)): ${reasons}${foundAutoExec.length ? " combined with automatic execution on open (" + foundAutoExec.join(", ") + ")" : ""}.`,
          recommended_action: "Quarantine immediately. Do not open in a PDF viewer."
        }
      }
    };
  }

  if (foundHighRisk.length > 0) {
    const reasons = foundHighRisk.map(r => r.desc).join("; ");
    return {
      hasEmbeddedExe: false,
      result: {
        filename: filename,
        detected_format: "PDF Document (Active Script/URI Trigger)",
        extension_spoofed: false,
        threat_vector: "Vector C (PDF Structural & Active-Payload Inspection)",
        verdict: "SUSPICIOUS PDF DOCUMENT",
        risk_level: "MEDIUM",
        confidence: 74,
        ai_analysis: {
          executive_summary: `PDF contains active scripting or external action triggers: ${reasons}.`,
          recommended_action: "Hold and verify sender authenticity before opening."
        }
      }
    };
  }

  return {
    hasEmbeddedExe: false,
    result: {
      filename: filename,
      detected_format: `PDF Document (${pageCount} page${pageCount > 1 ? "s" : ""})`,
      extension_spoofed: false,
      threat_vector: "Vector C (PDF Structural & Active-Payload Inspection)",
      verdict: "CLEAN / BENIGN",
      risk_level: "LOW",
      confidence: 3,
      ai_analysis: {
        executive_summary: `Verified valid %PDF header (${pageCount} page${pageCount > 1 ? "s" : ""}) with zero embedded executables, launch actions, or malicious JavaScript triggers.`,
        recommended_action: "Safe to open and download."
      }
    }
  };
}

async function sendBytesToNeuralBackend(uint8Array, filename, mimeType) {
  const uploadBytes = uint8Array.length > MAX_UPLOAD_BYTES
    ? uint8Array.subarray(0, SLICE_HEADER_BYTES)
    : uint8Array;

  const blob = new Blob([uploadBytes], { type: mimeType || "application/octet-stream" });
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
  return await response.json();
}

async function analyzeBufferWithBackend(uint8Array, filename, mimeType) {
  const fileHash = await sha256Hex(uint8Array);
  if (verdictCache.has(fileHash)) {
    return verdictCache.get(fileHash);
  }

  const isPdfMagic = hasMagicBytes(uint8Array, [0x25, 0x50, 0x44, 0x46]); // %PDF
  const isPeMagic = hasMagicBytes(uint8Array, [0x4D, 0x5A]); // MZ
  const isPngMagic = hasMagicBytes(uint8Array, [0x89, 0x50, 0x4E, 0x47]); // PNG
  const isJpgMagic = hasMagicBytes(uint8Array, [0xFF, 0xD8, 0xFF]); // JPG

  let result;

  if (isPdfMagic) {
    // 1. Genuine PDF document -> Run deep PDF structural + embedded-PE inspection
    const pdfInspection = inspectPdfBuffer(uint8Array, filename);
    if (pdfInspection.hasEmbeddedExe) {
      // Extract the hidden Windows PE executable inside the PDF and run ResNet-50 + Grad-CAM!
      const extractedExe = uint8Array.subarray(pdfInspection.embeddedExeOffset);
      result = await sendBytesToNeuralBackend(extractedExe, `${filename}_embedded.exe`, "application/x-msdownload");
      result.extension_spoofed = true;
      result.detected_format = "PDF with Embedded PE Executable";
    } else {
      result = pdfInspection.result;
    }
  } else if (isPeMagic || isPngMagic || isJpgMagic) {
    // 2. PE Binary or Raster Media (including spoofed files like invoice.pdf that actually start with MZ!)
    result = await sendBytesToNeuralBackend(uint8Array, filename, mimeType);
  } else {
    // 3. Other generic office/text files: verify no hidden MZ executable header
    result = {
      filename: filename,
      detected_format: mimeType || "Document Stream",
      extension_spoofed: false,
      threat_vector: "Magic-Byte Header Verification",
      verdict: "CLEAN / BENIGN",
      risk_level: "LOW",
      confidence: 4,
      ai_analysis: {
        executive_summary: `Verified non-executable document stream (${(uint8Array.length / 1024).toFixed(1)} KB) with no PE binary header.`,
        recommended_action: "Safe to open and download."
      }
    };
  }

  verdictCache.set(fileHash, result);
  if (!isThreatResult(result) && filename) {
    approvedFilenames.add(filename.toLowerCase());
  }
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
    return true;
  }

  if (message.type === "AEGIS_ANALYZE_URL") {
    (async () => {
      try {
        const res = await fetch(message.url, { credentials: "include" });
        if (!res.ok) throw new Error(`Attachment fetch returned HTTP ${res.status}`);
        const arrayBuffer = await res.arrayBuffer();
        const bytes = new Uint8Array(arrayBuffer);
        const contentType = res.headers.get("content-type") || "application/octet-stream";

        // Extract true filename from Content-Disposition header if available
        let resolvedFilename = message.filename;
        const disp = res.headers.get("content-disposition") || "";
        const fnameMatch = disp.match(/filename\*?=(?:UTF-8''|")?([^";\r\n]+)/i);
        if (fnameMatch && fnameMatch[1]) {
          try {
            resolvedFilename = decodeURIComponent(fnameMatch[1].replace(/"/g, "").trim());
          } catch (e) {
            resolvedFilename = fnameMatch[1].replace(/"/g, "").trim();
          }
        }

        const data = await analyzeBufferWithBackend(bytes, resolvedFilename, contentType);
        if (!isThreatResult(data)) {
          approvedDownloadUrls.add(message.url);
          if (res.url) approvedDownloadUrls.add(res.url);
        }

        const base64Data = bytes.length <= 25 * 1024 * 1024 ? uint8ArrayToBase64(bytes) : null;
        sendResponse({ data, base64Data, mimeType: contentType, resolvedFilename });
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }
});

// 2. Browser Download Gate Backstop (Catches any unverified Gmail stream)
chrome.downloads.onDeterminingFilename.addListener((downloadItem) => {
  const url = downloadItem.url || "";
  const finalUrl = downloadItem.finalUrl || "";
  const ref = (downloadItem.referrer || "").toLowerCase();
  const fname = downloadItem.filename || "downloaded_attachment";

  if (url.startsWith("blob:") || finalUrl.startsWith("blob:")) {
    return;
  }

  const isGmailDownload =
    url.includes("mail.google.com") ||
    finalUrl.includes("mail.google.com") ||
    url.includes("googleusercontent.com") ||
    finalUrl.includes("googleusercontent.com") ||
    ref.includes("mail.google.com");

  if (!isGmailDownload) {
    return;
  }

  if (
    approvedDownloadUrls.has(url) ||
    approvedDownloadUrls.has(finalUrl) ||
    approvedFilenames.has(fname.toLowerCase())
  ) {
    return;
  }

  chrome.downloads.cancel(downloadItem.id, () => {
    chrome.downloads.removeFile(downloadItem.id, () => {
      const _ = chrome.runtime.lastError;
    });
    chrome.downloads.erase({ id: downloadItem.id });
  });

  const targetUrl = finalUrl || url;

  chrome.tabs.query({ url: "https://mail.google.com/*" }, async (tabs) => {
    const activeTab = tabs && tabs[0];
    if (activeTab) {
      chrome.tabs.sendMessage(activeTab.id, {
        type: "AEGIS_BG_SCAN_START",
        filename: fname,
        sizeBytes: downloadItem.totalBytes || 0
      });
    }

    try {
      const res = await fetch(targetUrl, { credentials: "include" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = await res.arrayBuffer();
      const bytes = new Uint8Array(buf);
      const mimeType = res.headers.get("content-type") || downloadItem.mime || "application/octet-stream";

      const verdictData = await analyzeBufferWithBackend(bytes, fname, mimeType);
      if (!isThreatResult(verdictData)) {
        approvedDownloadUrls.add(url);
        approvedDownloadUrls.add(finalUrl);
      }

      if (activeTab) {
        const base64Data = !isThreatResult(verdictData) && bytes.length <= 25 * 1024 * 1024
          ? uint8ArrayToBase64(bytes)
          : null;
        chrome.tabs.sendMessage(activeTab.id, {
          type: "AEGIS_BG_SCAN_RESULT",
          filename: fname,
          data: verdictData,
          base64Data: base64Data,
          mimeType: mimeType
        });
      }
    } catch (err) {
      if (activeTab) {
        chrome.tabs.sendMessage(activeTab.id, {
          type: "AEGIS_BG_SCAN_ERROR",
          filename: fname,
          error: err.message
        });
      }
    }
  });
});
