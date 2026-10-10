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
    
    // Check for payment harvesting inputs by attribute names/autocomplete (NEVER reading values)
    const allInputs = document.querySelectorAll('input, select');
    let paymentCount = 0;
    allInputs.forEach(input => {
      const meta = ((input.name || '') + ' ' + (input.id || '') + ' ' + (input.autocomplete || '') + ' ' + (input.placeholder || '')).toLowerCase();
      if (meta.includes('card') || meta.includes('cvv') || meta.includes('pan') || meta.includes('cc-number') || meta.includes('cc-exp')) {
        paymentCount++;
      }
    });

    const externalFormCount = countExternalForms(forms);
    const externalIframeCount = countExternalIframes();

    return {
      has_password_input: passwordInputs.length > 0 ? 1 : 0,
      password_input_count: passwordInputs.length,
      has_payment_input: paymentCount > 0 ? 1 : 0,
      payment_input_count: paymentCount,
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

  // ─── Notification Component (Shadow DOM Isolated) ─────────────────────────
  let activeNotificationTimer = null;
  let activeNotificationHost = null;

  function showRiskNotification(data) {
    // Prevent duplicate DOM containers
    if (activeNotificationHost && activeNotificationHost.parentNode) {
      if (activeNotificationTimer) clearTimeout(activeNotificationTimer);
      activeNotificationHost.remove();
      activeNotificationHost = null;
    }

    const host = document.createElement('div');
    host.id = 'trustshield-notification-root';
    activeNotificationHost = host;

    const shadow = host.attachShadow({ mode: 'open' });

    const classification = (data.classification || 'inconclusive').toLowerCase();
    const score = Number.isFinite(data.risk_score) ? data.risk_score : '—';
    const hostname = data.url_host || window.location.hostname;
    const indicator = data.strongest_indicator || 'No critical threat indicators detected.';

    const themeColors = {
      low_risk: { color: '#22c55e', label: 'Low Risk', badgeBg: 'rgba(34, 197, 94, 0.15)', icon: '✓' },
      suspicious: { color: '#f59e0b', label: 'Suspicious', badgeBg: 'rgba(245, 158, 11, 0.15)', icon: '▲' },
      high_risk: { color: '#ef4444', label: 'High Risk', badgeBg: 'rgba(239, 68, 68, 0.15)', icon: '✕' },
      inconclusive: { color: '#94a3b8', label: 'Inconclusive', badgeBg: 'rgba(148, 163, 184, 0.15)', icon: '?' },
    };
    const theme = themeColors[classification] || themeColors.inconclusive;

    // Build style element
    const style = document.createElement('style');
    style.textContent = `
      :host {
        all: initial;
        position: fixed;
        bottom: 24px;
        right: 24px;
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      }
      .ts-toast {
        width: 340px;
        background: #0e1117;
        color: #e5e7eb;
        border: 1px solid #242b3a;
        border-left: 4px solid ${theme.color};
        border-radius: 8px;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.55), 0 2px 6px rgba(0, 0, 0, 0.4);
        padding: 14px 16px;
        box-sizing: border-box;
        animation: tsSlideIn 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        transition: opacity 0.3s ease, transform 0.3s ease;
      }
      .ts-toast.ts-hiding {
        opacity: 0;
        transform: translateY(12px);
      }
      @keyframes tsSlideIn {
        from { opacity: 0; transform: translateY(16px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .ts-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 6px;
      }
      .ts-brand-row {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .ts-brand-tag {
        font-family: "JetBrains Mono", Consolas, monospace;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 0.8px;
        color: #ccff00;
      }
      .ts-host {
        font-size: 12px;
        color: #9ca3af;
        font-weight: 500;
        max-width: 170px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .ts-close-btn {
        background: transparent;
        border: none;
        color: #6b7280;
        cursor: pointer;
        padding: 2px 6px;
        font-size: 14px;
        line-height: 1;
        border-radius: 4px;
        transition: color 0.15s ease, background 0.15s ease;
      }
      .ts-close-btn:hover {
        color: #ffffff;
        background: #1f2937;
      }
      .ts-score-row {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
      }
      .ts-score-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        font-family: "JetBrains Mono", Consolas, monospace;
        font-size: 12px;
        font-weight: 700;
        padding: 3px 8px;
        border-radius: 4px;
        background: ${theme.badgeBg};
        color: ${theme.color};
        border: 1px solid ${theme.color}40;
      }
      .ts-class-label {
        font-size: 12px;
        font-weight: 600;
        color: #d1d5db;
      }
      .ts-reason-box {
        font-size: 12px;
        color: #9ca3af;
        line-height: 1.45;
        margin-bottom: 12px;
        padding: 6px 8px;
        background: #161b22;
        border-radius: 4px;
        border: 1px solid #1f2937;
        word-break: break-word;
      }
      .ts-reason-strong {
        color: #f3f4f6;
        font-weight: 600;
      }
      .ts-actions {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: 8px;
      }
      .ts-btn {
        font-family: "JetBrains Mono", Consolas, monospace;
        font-size: 11px;
        font-weight: 600;
        padding: 5px 10px;
        border-radius: 4px;
        cursor: pointer;
        transition: all 0.15s ease;
        text-decoration: none;
      }
      .ts-btn-dismiss {
        background: #161b22;
        color: #9ca3af;
        border: 1px solid #242b3a;
      }
      .ts-btn-dismiss:hover {
        color: #ffffff;
        background: #1f2937;
      }
      .ts-btn-details {
        background: rgba(204, 255, 0, 0.12);
        color: #ccff00;
        border: 1px solid rgba(204, 255, 0, 0.35);
      }
      .ts-btn-details:hover {
        background: #ccff00;
        color: #0b0f02;
      }
    `;

    // Build container card with safe DOM construction
    const toast = document.createElement('div');
    toast.className = 'ts-toast';
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'polite');

    // Header
    const header = document.createElement('div');
    header.className = 'ts-header';

    const brandRow = document.createElement('div');
    brandRow.className = 'ts-brand-row';

    const brandTag = document.createElement('span');
    brandTag.className = 'ts-brand-tag';
    brandTag.textContent = 'TRUSTSHIELD';

    const hostSpan = document.createElement('span');
    hostSpan.className = 'ts-host';
    hostSpan.textContent = hostname;
    hostSpan.title = hostname;

    brandRow.appendChild(brandTag);
    brandRow.appendChild(document.createTextNode(' • '));
    brandRow.appendChild(hostSpan);

    const closeBtn = document.createElement('button');
    closeBtn.className = 'ts-close-btn';
    closeBtn.setAttribute('aria-label', 'Dismiss notification');
    closeBtn.textContent = '✕';

    header.appendChild(brandRow);
    header.appendChild(closeBtn);

    // Score & classification row
    const scoreRow = document.createElement('div');
    scoreRow.className = 'ts-score-row';

    const scoreBadge = document.createElement('span');
    scoreBadge.className = 'ts-score-badge';
    scoreBadge.textContent = `${theme.icon} ${score}/100`;

    const classLabel = document.createElement('span');
    classLabel.className = 'ts-class-label';
    classLabel.textContent = `— ${theme.label}`;

    scoreRow.appendChild(scoreBadge);
    scoreRow.appendChild(classLabel);

    // Reason box (strongest indicator)
    const reasonBox = document.createElement('div');
    reasonBox.className = 'ts-reason-box';

    const reasonLabel = document.createElement('span');
    reasonLabel.className = 'ts-reason-strong';
    reasonLabel.textContent = 'Indicator: ';

    const reasonText = document.createTextNode(indicator);

    reasonBox.appendChild(reasonLabel);
    reasonBox.appendChild(reasonText);

    // Actions row
    const actions = document.createElement('div');
    actions.className = 'ts-actions';

    const dismissBtn = document.createElement('button');
    dismissBtn.className = 'ts-btn ts-btn-dismiss';
    dismissBtn.textContent = 'Dismiss';

    const detailsBtn = document.createElement('button');
    detailsBtn.className = 'ts-btn ts-btn-details';
    detailsBtn.textContent = 'View Details';

    actions.appendChild(dismissBtn);
    actions.appendChild(detailsBtn);

    // Assemble toast
    toast.appendChild(header);
    toast.appendChild(scoreRow);
    toast.appendChild(reasonBox);
    toast.appendChild(actions);

    shadow.appendChild(style);
    shadow.appendChild(toast);

    document.documentElement.appendChild(host);

    // 5-second auto-dismiss with hover pause
    let remainingMs = 5000;
    let timerStart = Date.now();

    function dismiss() {
      if (activeNotificationTimer) {
        clearTimeout(activeNotificationTimer);
        activeNotificationTimer = null;
      }
      toast.classList.add('ts-hiding');
      setTimeout(() => {
        if (host && host.parentNode) {
          host.remove();
        }
        if (activeNotificationHost === host) {
          activeNotificationHost = null;
        }
      }, 300);
    }

    activeNotificationTimer = setTimeout(dismiss, remainingMs);

    toast.addEventListener('mouseenter', () => {
      if (activeNotificationTimer) {
        clearTimeout(activeNotificationTimer);
        activeNotificationTimer = null;
      }
      remainingMs = Math.max(1000, remainingMs - (Date.now() - timerStart));
    });

    toast.addEventListener('mouseleave', () => {
      timerStart = Date.now();
      activeNotificationTimer = setTimeout(dismiss, remainingMs);
    });

    closeBtn.addEventListener('click', dismiss);
    dismissBtn.addEventListener('click', dismiss);

    detailsBtn.addEventListener('click', () => {
      dismiss();
      try {
        const trustUrl = chrome.runtime.getURL('trust.html');
        window.open(trustUrl, '_blank');
      } catch (_) {
        // Fallback: alert
      }
    });
  }

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SHOW_RISK_NOTIFICATION') {
      if (message.result) {
        showRiskNotification(message.result);
      }
      sendResponse({ received: true });
      return false;
    }

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
