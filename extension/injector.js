/**
 * AegisSOC Edge Interceptor — Main-World Hook (injector.js)
 * Passively indexes decrypted WhatsApp Web / Gmail Blobs in a bounded ring buffer
 * and intercepts programmatic <a download> clicks before files write to disk.
 */
(function () {
  const MAX_BLOB_CACHE = 60;
  const MIN_SCAN_BYTES = 128;
  const MAX_UPLOAD_BYTES = 4 * 1024 * 1024; // 4 MB cap (slices 256KB header if larger)
  const SLICE_HEADER_BYTES = 256 * 1024;

  const blobRegistry = new Map();
  const approvedBlobUrls = new Set();

  // 1. Hook URL.createObjectURL to index decrypted Blobs lazily without network spam
  const originalCreateObjectURL = URL.createObjectURL;
  URL.createObjectURL = function (obj) {
    const objectUrl = originalCreateObjectURL.apply(this, arguments);
    try {
      if (obj instanceof Blob && obj.size >= MIN_SCAN_BYTES) {
        if (blobRegistry.size >= MAX_BLOB_CACHE) {
          const oldestKey = blobRegistry.keys().next().value;
          blobRegistry.delete(oldestKey);
        }
        blobRegistry.set(objectUrl, {
          blob: obj,
          size: obj.size,
          type: obj.type || "application/octet-stream",
          name: obj.name || null,
          createdAt: Date.now()
        });
      }
    } catch (err) {
      // Fail-safe: never break host page rendering
    }
    return objectUrl;
  };

  // Helper: Convert Blob/Slice to Base64 for IPC transfer to Isolated World
  function blobToBase64(blob) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        const res = String(reader.result || "");
        const base64 = res.includes(",") ? res.split(",")[1] : res;
        resolve(base64);
      };
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });
  }

  // Helper: Extract first 8 magic bytes as hex string
  async function getMagicHex(blob) {
    const slice = blob.slice(0, 8);
    const buf = await slice.arrayBuffer();
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, "0").toUpperCase())
      .join(" ");
  }

  // 2. Hook HTMLAnchorElement.prototype.click to catch WhatsApp Web programmatic downloads
  const originalAnchorClick = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function () {
    const href = this.href || "";
    const downloadAttr = this.getAttribute("download");

    if (href.startsWith("blob:") && !approvedBlobUrls.has(href)) {
      const entry = blobRegistry.get(href);
      if (entry && (downloadAttr !== null || entry.size > 512)) {
        const filename = downloadAttr || entry.name || "whatsapp_payload.bin";
        const anchorRef = this;

        (async () => {
          try {
            const magicHex = await getMagicHex(entry.blob);
            // Slice oversized binaries (>4MB) to first 256KB for Nataraj texture mapping
            const targetBlob = entry.blob.size > MAX_UPLOAD_BYTES
              ? entry.blob.slice(0, SLICE_HEADER_BYTES, entry.type)
              : entry.blob;
            const base64Data = await blobToBase64(targetBlob);

            window.dispatchEvent(new CustomEvent("AEGIS_INTERCEPTED_BLOB", {
              detail: {
                blobUrl: href,
                filename: filename,
                mimeType: entry.type,
                originalSize: entry.size,
                magicHex: magicHex,
                base64Data: base64Data
              }
            }));
          } catch (e) {
            // If serialization fails, allow normal click
            approvedBlobUrls.add(href);
            originalAnchorClick.call(anchorRef);
          }
        })();

        // Hold the download until AegisSOC verdict returns
        return;
      }
    }

    return originalAnchorClick.apply(this, arguments);
  };

  // 3. Listen for release or quarantine directive from Isolated Content Script
  window.addEventListener("AEGIS_BLOB_VERDICT", (event) => {
    const { blobUrl, filename, action } = event.detail || {};
    if (!blobUrl) return;

    if (action === "ALLOW") {
      approvedBlobUrls.add(blobUrl);
      const tempAnchor = document.createElement("a");
      tempAnchor.href = blobUrl;
      tempAnchor.download = filename || "verified_file";
      tempAnchor.style.display = "none";
      document.body.appendChild(tempAnchor);
      originalAnchorClick.call(tempAnchor);
      setTimeout(() => tempAnchor.remove(), 1000);
    } else if (action === "BLOCK") {
      blobRegistry.delete(blobUrl);
      try {
        URL.revokeObjectURL(blobUrl);
      } catch (e) {}
    }
  });
})();
