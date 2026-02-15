// Angell Fractal Security Architecture — Browser Extension
// Copyright 2025-2026 Nicholas Reid Angell. All rights reserved.
// Apache License 2.0

// Constants
const PHI = (1 + Math.sqrt(5)) / 2;
const NICHOLASBROT_C_RE = -0.4;
const NICHOLASBROT_C_IM = 0.6;
const DEFAULT_MAX_ITER = 100;
const DEFAULT_ESCAPE_RADIUS_SQ = 4.0;

// ============================================================
// CORE OPERATORS (JavaScript fallback — WASM replaces in production)
// ============================================================

function juliaIterate(zRe, zIm, cRe, cIm) {
  // z² + c
  const newRe = zRe * zRe - zIm * zIm + cRe;
  const newIm = 2 * zRe * zIm + cIm;
  return [newRe, newIm];
}

function gateOperator(zRe, zIm, maxIter = DEFAULT_MAX_ITER) {
  let re = zRe, im = zIm;
  for (let i = 0; i < maxIter; i++) {
    if (re * re + im * im > DEFAULT_ESCAPE_RADIUS_SQ) {
      return { verdict: "ESCAPED", iteration: i };
    }
    [re, im] = juliaIterate(re, im, NICHOLASBROT_C_RE, NICHOLASBROT_C_IM);
  }
  return { verdict: "BOUNDED", iteration: maxIter };
}

function brakeOperator(zRe, zIm, maxIter = DEFAULT_MAX_ITER) {
  const gate = gateOperator(zRe, zIm, maxIter);
  if (gate.verdict === "BOUNDED") {
    return { ...gate, threatScore: 0.0, action: "ALLOW" };
  }
  const score = 1.0 - (gate.iteration / maxIter);
  let action;
  if (score > 0.7) action = "BLOCK";
  else if (score > 0.3) action = "RATE_LIMIT";
  else action = "ALLOW";
  return { ...gate, threatScore: score, action };
}

// ============================================================
// FEATURE MAPPING
// ============================================================

function mapRequestToComplex(url, resourceType, timeStamp, prevTimeStamp) {
  // Map URL length as a proxy for packet complexity
  const urlLen = Math.min(url.length, 2000);
  const normLen = urlLen / 2000.0;

  // Map inter-request timing
  const iat = (prevTimeStamp !== null && prevTimeStamp !== undefined) ? (timeStamp - prevTimeStamp) : 1000;
  const logIat = Math.log10(Math.max(iat, 0.01) * 100) / 6.0;
  const normIat = Math.min(Math.max(logIat, 0), 1);

  const re = (normLen * 2.0 - 1.0) * 1.6;
  const im = (normIat * 2.0 - 1.0) * 1.6;

  return [re, im];
}

// ============================================================
// REQUEST MONITORING
// ============================================================

const domainStats = {};
let prevTimeStamp = null;

async function persistStats() {
  try {
    await chrome.storage.local.set({ domainStats });
  } catch (_) {
    // ignore
  }
}

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    const { url, type: resourceType, timeStamp } = details;

    try {
      const { enabled } = await chrome.storage.local.get({ enabled: true });
      if (!enabled) return;

      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      // Map to complex plane
      const [zRe, zIm] = mapRequestToComplex(url, resourceType, timeStamp, prevTimeStamp);
      prevTimeStamp = timeStamp;

      // Run Brake operator (includes Gate)
      const result = brakeOperator(zRe, zIm);

      // Track per-domain statistics
      if (!domainStats[domain]) {
        domainStats[domain] = {
          total: 0,
          bounded: 0,
          escaped: 0,
          blocked: 0,
          rateLimited: 0,
          maxThreatScore: 0,
          avgThreatScore: 0,
          threatScoreSum: 0,
        };
      }

      const stats = domainStats[domain];
      stats.total += 1;
      stats.threatScoreSum += result.threatScore;
      stats.avgThreatScore = stats.threatScoreSum / stats.total;
      stats.maxThreatScore = Math.max(stats.maxThreatScore, result.threatScore);

      if (result.verdict === "BOUNDED") {
        stats.bounded += 1;
      } else {
        stats.escaped += 1;
        if (result.action === "BLOCK") stats.blocked += 1;
        if (result.action === "RATE_LIMIT") stats.rateLimited += 1;
      }

      // Store for popup display
      await persistStats();
    } catch (_) {
      // Silently handle malformed URLs or API errors
    }
  },
  { urls: ["<all_urls>"] }
);

// ============================================================
// MESSAGE HANDLING (for popup)
// ============================================================

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message && message.type === "getStats") {
    sendResponse({ domainStats, phi: PHI });
    return true;
  }
  if (message && message.type === "clearStats") {
    Object.keys(domainStats).forEach((k) => delete domainStats[k]);
    chrome.storage.local.set({ domainStats: {} }).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }
  if (message && message.type === "classify") {
    const result = brakeOperator(message.zRe, message.zIm);
    sendResponse(result);
    return true;
  }
  sendResponse({ ok: false });
  return true;
});

console.log(`[Angell Fractal Security] Active | φ = ${PHI} | c = ${NICHOLASBROT_C_RE} + ${NICHOLASBROT_C_IM}i`);
