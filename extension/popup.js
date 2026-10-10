/**
 * TrustShield Popup Controller
 * Manages UI state transitions and communicates with the background service worker.
 */

'use strict';

// ─── Element References ────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const ui = {
  app:                $('app'),
  siteHostname:       $('siteHostname'),
  siteUrl:            $('siteUrl'),
  siteIcon:           $('siteIcon'),
  httpsBadge:         $('httpsBadge'),
  headerBadge:        $('headerBadge'),

  // States
  stateIdle:          $('stateIdle'),
  stateScanning:      $('stateScanning'),
  stateResults:       $('stateResults'),
  stateError:         $('stateError'),

  // Idle
  scanBtn:            $('scanBtn'),

  // Scanning
  scanningLabel:      $('scanningLabel'),
  step1:              $('step1'),
  step2:              $('step2'),
  step3:              $('step3'),

  // Results
  gaugeArc:           $('gaugeArc'),
  riskScore:          $('riskScore'),
  riskLabel:          $('riskLabel'),
  classificationBadge: $('classificationBadge'),
  classIcon:          $('classIcon'),
  classTitle:         $('classTitle'),
  classSubtitle:      $('classSubtitle'),
  signalsList:        $('signalsList'),
  noSignals:          $('noSignals'),
  recommendationText: $('recommendationText'),
  metaModelValue:     $('metaModelValue'),
  metaScanTime:       $('metaScanTime'),
  rescanBtn:          $('rescanBtn'),

  // Error
  errorTitle:         $('errorTitle'),
  errorDesc:          $('errorDesc'),
  retryBtn:           $('retryBtn'),
};

// ─── State ────────────────────────────────────────────────────────────────────
let currentTab = null;
let lastScanResult = null;

// ─── Scanning step labels ─────────────────────────────────────────────────────
const SCAN_STEP_LABELS = [
  'Analyzing URL structure…',
  'Extracting page signals…',
  'Running ML prediction…',
];

// ─── Classification display config ───────────────────────────────────────────
const CLASS_CONFIG = {
  low_risk: {
    title: 'Low Risk',
    subtitle: 'No significant threats detected',
    badgeClass: 'ts-classification--safe',
    iconClass: 'ts-class-icon--safe',
    headerBadgeClass: 'ts-header-badge--safe',
    gaugeColor: '#22c55e',
    riskLabelText: 'LOW RISK',
    icon: `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>`,
  },
  suspicious: {
    title: 'Suspicious',
    subtitle: 'Exercise caution on this site',
    badgeClass: 'ts-classification--warning',
    iconClass: 'ts-class-icon--warning',
    headerBadgeClass: 'ts-header-badge--warning',
    gaugeColor: '#f59e0b',
    riskLabelText: 'SUSPICIOUS',
    icon: `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>`,
  },
  high_risk: {
    title: 'High Risk',
    subtitle: 'Likely phishing or malicious site',
    badgeClass: 'ts-classification--danger',
    iconClass: 'ts-class-icon--danger',
    headerBadgeClass: 'ts-header-badge--danger',
    gaugeColor: '#ef4444',
    riskLabelText: 'HIGH RISK',
    icon: `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M13.477 14.89A6 6 0 015.11 6.524L13.477 14.89zm1.414-1.414L6.524 5.11A6 6 0 0114.89 13.476zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" clip-rule="evenodd"/></svg>`,
  },
};

// ─── Signal code → friendly name mapping ─────────────────────────────────────
const SIGNAL_NAMES = {
  ip_based_host:              'IP Address as Hostname',
  excessive_subdomains:       'Excessive Subdomains',
  at_symbol_in_url:           'Deceptive @ Symbol in URL',
  double_slash_redirect:      'Suspicious Redirect Pattern',
  no_https:                   'Insecure Connection (HTTP)',
  suspicious_tld:             'Suspicious Domain Extension',
  long_url:                   'Unusually Long URL',
  ip_with_keywords:           'IP Host with Credential Keywords',
  url_encoding:               'Suspicious URL Encoding',
  credential_form_external_submit: 'Credentials Submitted Externally',
  password_input_detected:    'Credential Input Detected',
  form_external_action:       'Form Submits to External Domain',
  ml_phishing_prediction:     'ML: Phishing Predicted',
  ml_uncertain:               'ML: Uncertain Classification',
  known_threat:               'Known Threat Match',
};

// ─── Utility functions ────────────────────────────────────────────────────────
function showState(stateName) {
  ['stateIdle', 'stateScanning', 'stateResults', 'stateError'].forEach(s => {
    const el = ui[s];
    if (el) el.hidden = (s !== stateName);
  });
}

function setHeaderBadge(cls) {
  ui.headerBadge.className = 'ts-header-badge';
  if (cls) ui.headerBadge.classList.add(cls);
}

function updateGauge(score, color) {
  // Arc circumference = π * r (half circle, r≈55) ≈ 172.79
  const totalArc = 172.79;
  const offset = totalArc - (score / 100) * totalArc;
  ui.gaugeArc.style.strokeDashoffset = offset;
  ui.gaugeArc.setAttribute('stroke', color);
}

function animateCounter(el, targetVal, durationMs = 600) {
  const start = parseInt(el.textContent) || 0;
  const startTime = performance.now();
  function step(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / durationMs, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    el.textContent = Math.round(start + (targetVal - start) * eased);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function formatMs(ms) {
  if (ms === null || ms === undefined) return '—';
  return ms < 1000 ? `${Math.round(ms)}ms` : `${(ms / 1000).toFixed(2)}s`;
}

// ─── Scanning animation ───────────────────────────────────────────────────────
let scanStepInterval = null;

function startScanAnimation() {
  let step = 0;
  const steps = [ui.step1, ui.step2, ui.step3];
  const dots = steps.map(s => s.querySelector('.ts-step-dot'));

  // Reset all steps
  steps.forEach((s, i) => {
    s.classList.remove('ts-scan-step--active', 'ts-scan-step--done');
    dots[i].className = 'ts-step-dot';
  });

  function advanceStep() {
    if (step > 0 && step <= steps.length) {
      steps[step - 1].classList.remove('ts-scan-step--active');
      steps[step - 1].classList.add('ts-scan-step--done');
      dots[step - 1].className = 'ts-step-dot ts-step-dot--done';
    }
    if (step < steps.length) {
      steps[step].classList.add('ts-scan-step--active');
      dots[step].className = 'ts-step-dot ts-step-dot--active';
      ui.scanningLabel.textContent = SCAN_STEP_LABELS[step];
      step++;
    }
  }

  advanceStep();
  scanStepInterval = setInterval(() => {
    if (step < steps.length) {
      advanceStep();
    }
  }, 900);
}

function stopScanAnimation() {
  if (scanStepInterval) {
    clearInterval(scanStepInterval);
    scanStepInterval = null;
  }
}

// ─── Results rendering ────────────────────────────────────────────────────────
function renderResults(result) {
  const classification = result.classification || 'low_risk';
  const cfg = CLASS_CONFIG[classification] || CLASS_CONFIG.low_risk;
  const score = result.risk_score ?? 0;

  // Risk score gauge
  updateGauge(score, cfg.gaugeColor);
  animateCounter(ui.riskScore, score);
  ui.riskLabel.textContent = cfg.riskLabelText;
  ui.riskLabel.style.color = cfg.gaugeColor;

  // Classification badge
  ui.classificationBadge.className = `ts-classification ${cfg.badgeClass}`;
  ui.classIcon.className = `ts-class-icon ${cfg.iconClass}`;
  ui.classIcon.innerHTML = cfg.icon;
  ui.classTitle.textContent = cfg.title;
  if (classification === 'low_risk' && result.score_breakdown?.evidence_level === 'limited') {
    ui.classSubtitle.textContent = 'Limited evidence • Verify before downloading';
  } else {
    ui.classSubtitle.textContent = cfg.subtitle;
  }

  // Header badge
  setHeaderBadge(cfg.headerBadgeClass);

  // Signals
  renderSignals(result.signals || []);

  // Recommendation
  ui.recommendationText.textContent = result.recommendation || 'No recommendation available.';

  // Meta info
  ui.metaModelValue.textContent = result.model_available
    ? (result.performance?.local_only ? 'Heuristic + ML' : 'ML + Heuristic')
    : (result.performance?.local_only ? 'Heuristic only' : 'Heuristic + ML');

  if (result.api_error && !result.model_available) {
    ui.metaModelValue.textContent = 'Local heuristic';
  }

  ui.metaScanTime.textContent = formatMs(result.performance?.total_scan_ms);

  showState('stateResults');
}

function renderSignals(signals) {
  ui.signalsList.innerHTML = '';

  if (!signals || signals.length === 0) {
    ui.noSignals.hidden = false;
    return;
  }

  ui.noSignals.hidden = true;

  // Sort: high → medium → low
  const severityOrder = { high: 0, medium: 1, low: 2 };
  const sorted = [...signals].sort((a, b) =>
    (severityOrder[a.severity] ?? 2) - (severityOrder[b.severity] ?? 2)
  );

  sorted.forEach((signal, index) => {
    const item = document.createElement('div');
    item.className = `ts-signal-item ts-signal-item--${signal.severity}`;
    item.setAttribute('role', 'listitem');
    item.style.animationDelay = `${index * 50}ms`;

    const friendlyName = SIGNAL_NAMES[signal.code] || signal.code.replace(/_/g, ' ');

    item.innerHTML = `
      <div class="ts-signal-dot ts-signal-dot--${signal.severity}"></div>
      <div class="ts-signal-content">
        <div class="ts-signal-name">${escapeHtml(friendlyName)}</div>
        <div class="ts-signal-desc">${escapeHtml(signal.description || '')}</div>
      </div>
      <div class="ts-signal-severity ts-signal-severity--${signal.severity}">${escapeHtml(signal.severity)}</div>
    `;

    ui.signalsList.appendChild(item);
  });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ─── Tab info ─────────────────────────────────────────────────────────────────
async function loadCurrentTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;

    if (!tab || !tab.url) {
      ui.siteHostname.textContent = 'No active tab';
      ui.siteUrl.textContent = '';
      return;
    }

    const url = tab.url;

    // Restricted URLs
    const restricted = ['chrome://', 'chrome-extension://', 'about:', 'data:', 'edge://', 'brave://'];
    if (restricted.some(s => url.startsWith(s))) {
      ui.siteHostname.textContent = 'Browser page';
      ui.siteUrl.textContent = url.split('/').slice(0, 3).join('/');
      ui.scanBtn.disabled = true;
      ui.scanBtn.title = 'Cannot analyze browser-internal pages';
      return;
    }

    let parsed;
    try {
      parsed = new URL(url);
    } catch (_) {
      ui.siteHostname.textContent = 'Invalid URL';
      return;
    }

    ui.siteHostname.textContent = parsed.hostname;
    ui.siteUrl.textContent = url.length > 45 ? url.substring(0, 42) + '…' : url;
    ui.siteUrl.title = url;

    // HTTPS badge
    if (parsed.protocol === 'https:') {
      ui.httpsBadge.textContent = 'HTTPS';
      ui.httpsBadge.className = 'ts-https-badge ts-https-badge--secure';
    } else {
      ui.httpsBadge.textContent = 'HTTP';
      ui.httpsBadge.className = 'ts-https-badge ts-https-badge--insecure';
    }

  } catch (err) {
    console.error('[TrustShield Popup] loadCurrentTab error:', err);
    ui.siteHostname.textContent = 'Error loading tab';
  }
}

// ─── Scan logic ───────────────────────────────────────────────────────────────
async function performScan() {
  if (!currentTab || !currentTab.url) return;

  showState('stateScanning');
  setHeaderBadge('ts-header-badge--scanning');
  startScanAnimation();

  try {
    const result = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        type: 'SCAN_REQUEST',
        url: currentTab.url,
        tabId: currentTab.id,
      }, response => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!response) {
          reject(new Error('No response from background'));
          return;
        }
        if (!response.success) {
          reject(new Error(response.error || 'Scan failed'));
          return;
        }
        resolve(response.result);
      });
    });

    stopScanAnimation();
    lastScanResult = result;

    if (result.error) {
      showError('Cannot Analyze Page', result.message || 'This page type cannot be analyzed.');
    } else {
      renderResults(result);
    }

  } catch (err) {
    stopScanAnimation();
    console.error('[TrustShield Popup] Scan error:', err);
    showError('Scan Failed', err.message || 'An unexpected error occurred during analysis.');
  }
}

function showError(title, desc) {
  ui.errorTitle.textContent = title;
  ui.errorDesc.textContent = desc;
  setHeaderBadge('');
  showState('stateError');
}

// ─── Event Listeners ──────────────────────────────────────────────────────────
ui.scanBtn.addEventListener('click', performScan);
ui.rescanBtn.addEventListener('click', performScan);
ui.retryBtn.addEventListener('click', performScan);

// ─── Init ─────────────────────────────────────────────────────────────────────
(async function init() {
  await loadCurrentTab();
})();
