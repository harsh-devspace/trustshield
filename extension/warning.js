/**
 * TrustShield Warning Page Controller
 * Reads scan result from URL parameters (passed by background.js)
 * and populates the warning page UI.
 */

'use strict';

(function () {
  const params = new URLSearchParams(window.location.search);
  const resultParam = params.get('result');
  const targetUrl = params.get('url') || '';

  // Parse result
  let result = null;
  try {
    if (resultParam) result = JSON.parse(decodeURIComponent(resultParam));
  } catch (_) {}

  // Populate destination
  const hostnameEl = document.getElementById('destHostname');
  const fullUrlEl = document.getElementById('destFullUrl');
  const riskBarEl = document.getElementById('riskBar');
  const riskScoreEl = document.getElementById('riskScoreDisplay');
  const riskClassEl = document.getElementById('riskClassDisplay');
  const signalsListEl = document.getElementById('warningSignalsList');

  try {
    const parsed = new URL(targetUrl);
    hostnameEl.textContent = parsed.hostname;
    fullUrlEl.textContent = targetUrl.length > 60 ? targetUrl.substring(0, 57) + '…' : targetUrl;
  } catch (_) {
    hostnameEl.textContent = targetUrl || 'Unknown site';
  }

  // Risk score
  const score = result?.risk_score ?? 85;
  riskScoreEl.textContent = score;
  setTimeout(() => { riskBarEl.style.width = score + '%'; }, 100);

  const classification = result?.classification || 'high_risk';
  const classLabels = { high_risk: 'HIGH RISK', suspicious: 'SUSPICIOUS', low_risk: 'LOW RISK' };
  riskClassEl.textContent = classLabels[classification] || 'HIGH RISK';

  // Signals
  const signals = result?.signals || [];
  if (signals.length > 0) {
    signals.forEach(signal => {
      const li = document.createElement('li');
      li.className = `ts-signal-item ts-signal-item--${signal.severity}`;
      li.setAttribute('role', 'listitem');

      const nameMap = {
        ip_based_host: 'IP Address as Hostname',
        excessive_subdomains: 'Excessive Subdomains',
        at_symbol_in_url: 'Deceptive @ Symbol in URL',
        double_slash_redirect: 'Suspicious Redirect Pattern',
        no_https: 'Insecure Connection',
        suspicious_tld: 'Suspicious Domain Extension',
        long_url: 'Unusually Long URL',
        credential_form_external_submit: 'Credentials Submitted Externally',
        form_external_action: 'Form Submits to External Domain',
        ml_phishing_prediction: 'ML: Phishing Predicted',
      };

      const name = nameMap[signal.code] || signal.code.replace(/_/g, ' ');

      li.innerHTML = `
        <div class="ts-signal-dot ts-signal-dot--${signal.severity}"></div>
        <div class="ts-signal-content">
          <div class="ts-signal-name">${escapeHtml(name)}</div>
          <div class="ts-signal-desc">${escapeHtml(signal.description || '')}</div>
        </div>
      `;
      signalsListEl.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.className = 'ts-signal-item';
    li.textContent = 'Multiple suspicious indicators detected by ML analysis.';
    signalsListEl.appendChild(li);
  }

  // Button handlers
  document.getElementById('goBackBtn').addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  document.getElementById('proceedBtn').addEventListener('click', () => {
    if (targetUrl) {
      // Navigate to the target URL — user has explicitly chosen to proceed
      window.location.href = targetUrl;
    } else {
      window.close();
    }
  });

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
})();
