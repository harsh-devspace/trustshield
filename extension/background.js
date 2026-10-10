/**
 * TrustShield Background Service Worker
 * Handles navigation monitoring, API communication, and scan state management.
 * 
 * Architecture note: This service worker runs in isolation and communicates
 * with the popup and content scripts via chrome.runtime.sendMessage.
 */

const CONFIG = {
  API_BASE_URL: 'http://localhost:8000',
  API_TIMEOUT_MS: 5000,
  CACHE_TTL_MS: 5 * 60 * 1000,  // 5 minutes
  HIGH_RISK_THRESHOLD: 70,
  SUSPICIOUS_THRESHOLD: 40,
  // Restricted URL schemes that must never be analyzed or blocked
  RESTRICTED_SCHEMES: ['chrome://', 'chrome-extension://', 'about:', 'data:', 'file://', 'edge://', 'brave://'],
};

// In-memory cache for scan results (cleared on service worker restart)
const scanCache = new Map();

/**
 * Check if a URL is restricted (browser-internal, extension, etc.)
 * We must never attempt to analyze or block these.
 */
function isRestrictedUrl(url) {
  if (!url) return true;
  return CONFIG.RESTRICTED_SCHEMES.some(scheme => url.startsWith(scheme));
}

/**
 * Extract minimal features from a URL string (no network requests).
 * These features are sent to the backend for ML prediction.
 * NO page content, cookies, passwords, or browsing history is included.
 */
function extractUrlFeatures(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    const path = parsed.pathname;
    const query = parsed.search;
    const fullUrl = url;

    // Feature: URL length
    const urlLength = fullUrl.length;

    // Feature: hostname length
    const hostnameLength = hostname.length;

    // Feature: subdomain count
    const subdomainCount = hostname.split('.').length - 2;

    // Feature: uses HTTPS
    const isHttps = parsed.protocol === 'https:' ? 1 : 0;

    // Feature: IP address as hostname
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const hasIpHost = ipPattern.test(hostname) ? 1 : 0;

    // Feature: has @ in URL (common phishing trick)
    const hasAtSymbol = fullUrl.includes('@') ? 1 : 0;

    // Feature: double slash in path (not counting protocol)
    const pathAfterProtocol = fullUrl.slice(fullUrl.indexOf('//') + 2);
    const hasDoubleSlash = pathAfterProtocol.includes('//') ? 1 : 0;

    // Feature: dash in hostname
    const dashInHostname = hostname.includes('-') ? 1 : 0;

    // Feature: number of dots in URL
    const dotCount = (fullUrl.match(/\./g) || []).length;

    // Feature: has suspicious keywords in URL
    const suspiciousKeywords = ['login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm', 'bank', 'paypal', 'password', 'credential'];
    const hasSuspiciousKeywords = suspiciousKeywords.some(k => fullUrl.toLowerCase().includes(k)) ? 1 : 0;

    // Feature: path length
    const pathLength = path.length;

    // Feature: query string length
    const queryLength = query.length;

    // Feature: has port
    const hasPort = parsed.port ? 1 : 0;

    // Feature: TLD is suspicious (common in phishing)
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.xyz', '.click', '.club'];
    const hasSuspiciousTld = suspiciousTlds.some(tld => hostname.endsWith(tld)) ? 1 : 0;

    // Feature: excessive special characters in URL
    const specialCharCount = (fullUrl.match(/[!@#$%^&*()_+=\[\]{}|;':",.<>?]/g) || []).length;

    // Feature: number of slashes in path
    const slashCount = (path.match(/\//g) || []).length;

    // Feature: has encoded characters
    const hasEncoding = fullUrl.includes('%') ? 1 : 0;

    return {
      url_length: urlLength,
      hostname_length: hostnameLength,
      subdomain_count: Math.max(0, subdomainCount),
      is_https: isHttps,
      has_ip_host: hasIpHost,
      has_at_symbol: hasAtSymbol,
      has_double_slash: hasDoubleSlash,
      dash_in_hostname: dashInHostname,
      dot_count: dotCount,
      has_suspicious_keywords: hasSuspiciousKeywords,
      path_length: pathLength,
      query_length: queryLength,
      has_port: hasPort,
      has_suspicious_tld: hasSuspiciousTld,
      special_char_count: specialCharCount,
      slash_count: slashCount,
      has_encoding: hasEncoding,
    };
  } catch (e) {
    console.warn('[TrustShield] Feature extraction failed:', e.message);
    return null;
  }
}

/**
 * Call the backend API for ML-based risk analysis.
 * Sends only derived URL features — no raw HTML, cookies, or user data.
 */
async function callBackendApi(url, urlFeatures, domFeatures) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), CONFIG.API_TIMEOUT_MS);

  try {
    const response = await fetch(`${CONFIG.API_BASE_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: url,
        url_features: urlFeatures,
        dom_features: domFeatures || {},
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }

    return await response.json();
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      throw new Error('Backend API timed out after ' + CONFIG.API_TIMEOUT_MS + 'ms');
    }
    throw err;
  }
}

/**
 * Get DOM features from the active tab via content script.
 * These are structural signals only — no form values, passwords, or text content.
 */
async function getDomFeatures(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        // Extract only structural DOM signals — NOT content/values
        const forms = document.querySelectorAll('form');
        const passwordInputs = document.querySelectorAll('input[type="password"]');
        const externalForms = [];

        forms.forEach(form => {
          const action = form.action || '';
          try {
            const actionUrl = new URL(action, window.location.href);
            if (actionUrl.hostname !== window.location.hostname && action !== '') {
              externalForms.push(actionUrl.hostname);
            }
          } catch (_) {}
        });

        const iframes = document.querySelectorAll('iframe');
        const externalIframes = [];
        iframes.forEach(iframe => {
          const src = iframe.src || '';
          try {
            const iframeUrl = new URL(src);
            if (iframeUrl.hostname !== window.location.hostname) {
              externalIframes.push(iframeUrl.hostname);
            }
          } catch (_) {}
        });

        return {
          has_password_input: passwordInputs.length > 0 ? 1 : 0,
          password_input_count: passwordInputs.length,
          form_count: forms.length,
          external_form_count: externalForms.length,
          external_iframe_count: externalIframes.length,
          has_external_form: externalForms.length > 0 ? 1 : 0,
          title_length: document.title.length,
          has_favicon: document.querySelector('link[rel*="icon"]') ? 1 : 0,
        };
      },
    });

    return results?.[0]?.result || {};
  } catch (err) {
    console.warn('[TrustShield] DOM feature extraction failed:', err.message);
    return {};
  }
}

/**
 * Perform local heuristic analysis without any network calls.
 * Returns a list of signals detected locally.
 */
function localHeuristicAnalysis(url, urlFeatures) {
  const signals = [];
  let localScore = 0;

  if (!urlFeatures) return { signals, localScore };

  if (urlFeatures.has_ip_host) {
    signals.push({ code: 'ip_based_host', severity: 'high', description: 'The website uses an IP address instead of a domain name, which is unusual for legitimate sites.' });
    localScore += 30;
  }

  if (urlFeatures.subdomain_count > 3) {
    signals.push({ code: 'excessive_subdomains', severity: 'medium', description: `The URL has ${urlFeatures.subdomain_count} subdomain levels, which is atypical for legitimate websites.` });
    localScore += 15;
  }

  if (urlFeatures.has_at_symbol) {
    signals.push({ code: 'at_symbol_in_url', severity: 'high', description: 'The URL contains an @ symbol, a known phishing technique to disguise the real destination.' });
    localScore += 25;
  }

  if (urlFeatures.has_double_slash) {
    signals.push({ code: 'double_slash_redirect', severity: 'medium', description: 'The URL contains a suspicious double slash pattern that may indicate a redirect attempt.' });
    localScore += 15;
  }

  if (!urlFeatures.is_https) {
    signals.push({ code: 'no_https', severity: 'medium', description: 'The site does not use HTTPS encryption. Any data you submit may be intercepted.' });
    localScore += 15;
  }

  if (urlFeatures.has_suspicious_tld) {
    signals.push({ code: 'suspicious_tld', severity: 'medium', description: 'The domain uses a top-level domain commonly associated with low-cost or disposable phishing sites.' });
    localScore += 20;
  }

  if (urlFeatures.url_length > 100) {
    signals.push({ code: 'long_url', severity: 'low', description: `The URL is unusually long (${urlFeatures.url_length} characters), which is sometimes used to obscure the real destination.` });
    localScore += 8;
  }

  if (urlFeatures.has_suspicious_keywords && urlFeatures.has_ip_host) {
    signals.push({ code: 'ip_with_keywords', severity: 'high', description: 'An IP-based URL with login/account keywords is a strong phishing indicator.' });
    localScore += 20;
  } else if (urlFeatures.has_suspicious_keywords) {
    // Don't flag keywords alone as this would cause too many false positives on legitimate login pages
  }

  if (urlFeatures.has_encoding) {
    signals.push({ code: 'url_encoding', severity: 'low', description: 'The URL contains percent-encoded characters, which may be used to obscure content.' });
    localScore += 5;
  }

  return { signals, localScore: Math.min(localScore, 100) };
}

/**
 * Run a complete website scan and return structured results.
 * This is the main analysis pipeline.
 */
async function runScan(url, tabId) {
  const scanStart = Date.now();

  if (isRestrictedUrl(url)) {
    return {
      error: 'restricted_url',
      message: 'This page cannot be analyzed (browser-internal page).',
      url,
    };
  }

  // Check cache first
  const cacheKey = url;
  const cached = scanCache.get(cacheKey);
  if (cached && (Date.now() - cached.timestamp) < CONFIG.CACHE_TTL_MS) {
    return { ...cached.result, from_cache: true };
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch (_) {
    return { error: 'invalid_url', message: 'Invalid URL format.', url };
  }

  // Extract URL features (no network calls)
  const urlFeatures = extractUrlFeatures(url);

  // Get DOM features from tab (structural only, no content)
  let domFeatures = {};
  if (tabId) {
    domFeatures = await getDomFeatures(tabId);
  }

  // Local heuristic analysis (always available, no network)
  const { signals: heuristicSignals, localScore } = localHeuristicAnalysis(url, urlFeatures);

  // DOM-based signals
  const domSignals = [];
  if (domFeatures.has_password_input && domFeatures.has_external_form) {
    domSignals.push({
      code: 'credential_form_external_submit',
      severity: 'high',
      description: 'The page contains a password field whose form submits data to an external domain — a strong phishing indicator.',
    });
  } else if (domFeatures.has_password_input) {
    domSignals.push({
      code: 'password_input_detected',
      severity: 'low',
      description: 'The page requests login credentials. Verify the domain is legitimate before entering your password.',
    });
  }

  if (domFeatures.external_form_count > 0) {
    domSignals.push({
      code: 'form_external_action',
      severity: 'medium',
      description: `${domFeatures.external_form_count} form(s) on this page submit to a different domain.`,
    });
  }

  // Try backend API for ML prediction
  let apiResult = null;
  let apiError = null;
  let backendLatencyMs = null;

  try {
    const apiStart = Date.now();
    apiResult = await callBackendApi(url, urlFeatures, domFeatures);
    backendLatencyMs = Date.now() - apiStart;
  } catch (err) {
    apiError = err.message;
    console.warn('[TrustShield] Backend unavailable, using local analysis only:', err.message);
  }

  // Combine all signals
  const allSignals = [...heuristicSignals, ...domSignals];

  // Calculate final risk score
  let finalScore;
  let modelAvailable = false;

  if (apiResult && typeof apiResult.risk_score === 'number') {
    // Blend API result with local heuristics
    // Local signals that are very high confidence can override a low ML score
    const hasHighConfidenceLocal = heuristicSignals.some(s => s.severity === 'high') ||
      domSignals.some(s => s.severity === 'high');

    if (hasHighConfidenceLocal) {
      finalScore = Math.max(apiResult.risk_score, localScore);
    } else {
      // Weighted blend: 70% ML, 30% heuristic
      finalScore = Math.round(0.7 * apiResult.risk_score + 0.3 * localScore);
    }

    modelAvailable = apiResult.model_available !== false;

    // Add any signals from the API that aren't duplicated locally
    if (apiResult.signals) {
      const localCodes = new Set(allSignals.map(s => s.code));
      apiResult.signals.forEach(s => {
        if (!localCodes.has(s.code)) allSignals.push(s);
      });
    }
  } else {
    finalScore = localScore;
  }

  finalScore = Math.max(0, Math.min(100, Math.round(finalScore)));

  // Determine classification
  let classification;
  let recommendation;

  if (finalScore >= CONFIG.HIGH_RISK_THRESHOLD) {
    classification = 'high_risk';
    recommendation = 'Do not enter passwords, payment details, or personal information on this site. Navigate away using your browser\'s back button.';
  } else if (finalScore >= CONFIG.SUSPICIOUS_THRESHOLD) {
    classification = 'suspicious';
    recommendation = 'Exercise caution. Verify this website\'s identity before entering any sensitive information.';
  } else {
    classification = 'low_risk';
    recommendation = allSignals.length > 0
      ? 'No critical threats detected, but review the noted indicators before sharing sensitive data.'
      : 'No significant threats detected. Continue browsing safely.';
  }

  const totalScanMs = Date.now() - scanStart;

  const result = {
    url,
    url_host: parsed.hostname,
    risk_score: finalScore,
    classification,
    signals: allSignals,
    recommendation,
    model_available: modelAvailable,
    api_error: apiError,
    performance: {
      total_scan_ms: totalScanMs,
      backend_latency_ms: backendLatencyMs,
      local_only: !apiResult,
    },
    scanned_at: new Date().toISOString(),
    from_cache: false,
  };

  // Cache result
  scanCache.set(cacheKey, { result, timestamp: Date.now() });

  // Update extension badge
  updateBadge(tabId, classification);

  return result;
}

/**
 * Update the extension action badge to reflect the current risk level.
 */
function updateBadge(tabId, classification) {
  if (!tabId) return;

  const badgeConfig = {
    high_risk:   { text: '!', color: '#ef4444' },
    suspicious:  { text: '?', color: '#f59e0b' },
    low_risk:    { text: '✓', color: '#22c55e' },
  };

  const config = badgeConfig[classification] || { text: '', color: '#64748b' };

  try {
    chrome.action.setBadgeText({ text: config.text, tabId });
    chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
  } catch (err) {
    console.warn('[TrustShield] Badge update failed:', err.message);
  }
}

// ─── Message Handler ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_REQUEST') {
    const { url, tabId } = message;

    runScan(url, tabId).then(result => {
      sendResponse({ success: true, result });
    }).catch(err => {
      console.error('[TrustShield] Scan failed:', err);
      sendResponse({ success: false, error: err.message });
    });

    return true; // Keep message channel open for async response
  }

  if (message.type === 'CLEAR_BADGE') {
    try {
      chrome.action.setBadgeText({ text: '', tabId: message.tabId });
    } catch (_) {}
    sendResponse({ success: true });
    return false;
  }

  if (message.type === 'GET_CONFIG') {
    sendResponse({ config: CONFIG });
    return false;
  }

  if (message.type === 'CONTENT_FEATURES') {
    // Content script sending DOM features for a cached or in-progress scan
    // Store for potential re-scan
    sendResponse({ received: true });
    return false;
  }
});

// ─── Navigation Monitoring ────────────────────────────────────────────────────

// Monitor completed navigations to clear badge on new pages
chrome.webNavigation.onCompleted.addListener(details => {
  if (details.frameId !== 0) return; // Only main frame
  if (isRestrictedUrl(details.url)) return;

  // Clear badge on navigation (user must rescan)
  try {
    chrome.action.setBadgeText({ text: '', tabId: details.tabId });
  } catch (_) {}
});

console.log('[TrustShield] Background service worker initialized.');
