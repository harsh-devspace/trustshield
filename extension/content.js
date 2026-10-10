/**
 * TrustShield Content Script
 * Runs in the context of web pages (document_idle).
 * 
 * PRIVACY GUARANTEE: This script NEVER captures form values, passwords,
 * cookies, localStorage contents, or any sensitive user data.
 * It only extracts structural DOM signals (element counts, form attributes).
 */

(function () {
  'use strict';

  // Guard: don't run on restricted pages
  const href = window.location.href;
  if (!href.startsWith('http://') && !href.startsWith('https://')) {
    return;
  }

  /**
   * Extract structural DOM features only.
   * No content, no values, no sensitive data.
   */
  function extractDomFeatures() {
    const forms = document.querySelectorAll('form');
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const externalFormCount = countExternalForms(forms);
    const externalIframeCount = countExternalIframes();

    return {
      has_password_input: passwordInputs.length > 0 ? 1 : 0,
      password_input_count: passwordInputs.length,
      form_count: forms.length,
      external_form_count: externalFormCount,
      external_iframe_count: externalIframeCount,
      has_external_form: externalFormCount > 0 ? 1 : 0,
      title_length: document.title.length,
      has_favicon: document.querySelector('link[rel*="icon"]') ? 1 : 0,
    };
  }

  function countExternalForms(forms) {
    let count = 0;
    forms.forEach(form => {
      try {
        const action = form.getAttribute('action') || '';
        if (!action || action.startsWith('#') || action.startsWith('javascript:')) return;
        const actionUrl = new URL(action, window.location.href);
        if (actionUrl.hostname !== window.location.hostname) count++;
      } catch (_) {}
    });
    return count;
  }

  function countExternalIframes() {
    let count = 0;
    document.querySelectorAll('iframe').forEach(iframe => {
      try {
        const src = iframe.getAttribute('src') || '';
        if (!src) return;
        const iframeUrl = new URL(src, window.location.href);
        if (iframeUrl.hostname !== window.location.hostname) count++;
      } catch (_) {}
    });
    return count;
  }

  // Send DOM features to background on page load
  try {
    const features = extractDomFeatures();
    chrome.runtime.sendMessage({
      type: 'CONTENT_FEATURES',
      url: href,
      features,
    }).catch(() => {
      // Background service worker may not be ready; that's OK
    });
  } catch (_) {}

  // Listen for feature requests from popup
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_DOM_FEATURES') {
      try {
        sendResponse({ success: true, features: extractDomFeatures() });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
      return false;
    }
  });

})();
