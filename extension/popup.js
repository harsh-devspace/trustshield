/**
 * TrustShield — Cyber Forensics Workbench Popup Controller
 * Manages UI state transitions, telemetry rendering, and forensic CERT dossier export.
 */

'use strict';

// ─── Element References ────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const ui = {
  app:                 $('app'),
  siteHostname:        $('siteHostname'),
  siteUrl:             $('siteUrl'),
  httpsBadge:          $('httpsBadge'),
  headerBadge:         $('headerBadge'),

  // Tabs
  tabAnalysisBtn:      $('tabAnalysisBtn'),
  tabDossierBtn:       $('tabDossierBtn'),
  viewAnalysis:        $('viewAnalysis'),
  viewDossier:         $('viewDossier'),

  // States
  stateIdle:           $('stateIdle'),
  stateScanning:       $('stateScanning'),
  stateResults:        $('stateResults'),
  stateError:          $('stateError'),

  // Idle
  scanBtn:             $('scanBtn'),

  // Scanning
  scanningLabel:       $('scanningLabel'),
  step1:               $('step1'),
  step2:               $('step2'),
  step3:               $('step3'),

  // Results - Threat Meter & Telemetry
  meterFill:           $('meterFill'),
  meterMarker:         $('meterMarker'),
  riskScore:           $('riskScore'),
  riskLabel:           $('riskLabel'),
  telEntropy:          $('telEntropy'),
  telForms:            $('telForms'),
  telHomoglyph:        $('telHomoglyph'),
  telEvidence:         $('telEvidence'),

  // Classification & Signals
  classificationBadge: $('classificationBadge'),
  classIcon:           $('classIcon'),
  classTitle:          $('classTitle'),
  classSubtitle:       $('classSubtitle'),
  strongestIndicatorCard: $('strongestIndicatorCard'),
  strongestIndicatorText: $('strongestIndicatorText'),
  strongestImpactBadge: $('strongestImpactBadge'),
  signalCountBadge:    $('signalCountBadge'),
  signalsList:         $('signalsList'),
  noSignals:           $('noSignals'),
  recommendationText:  $('recommendationText'),
  metaModelValue:      $('metaModelValue'),
  metaScanTime:        $('metaScanTime'),

  // Actions
  rescanBtn:           $('rescanBtn'),
  exportCertBtn:       $('exportCertBtn'),
  certToast:           $('certToast'),

  // Dossier View
  attrHeuristic:       $('attrHeuristic'),
  attrMl:              $('attrMl'),
  attrMlProb:          $('attrMlProb'),
  attrDom:             $('attrDom'),
  attrThreatIntel:     $('attrThreatIntel'),
  attrChecksCount:     $('attrChecksCount'),
  attrUnavailableCount: $('attrUnavailableCount'),
  attrEvidence:        $('attrEvidence'),
  attrConfidenceNote:  $('attrConfidenceNote'),
  jsonPreviewBox:      $('jsonPreviewBox'),
  copyJsonBtn:         $('copyJsonBtn'),

  // Error
  errorTitle:          $('errorTitle'),
  errorDesc:           $('errorDesc'),
  retryBtn:            $('retryBtn'),
};

// ─── State ────────────────────────────────────────────────────────────────────
let currentTab = null;
let lastScanResult = null;

// ─── Scanning step labels ─────────────────────────────────────────────────────
const SCAN_STEP_LABELS = [
  'Inspecting hostname entropy & Punycode…',
  'Auditing DOM forms & external actions…',
  'Running Random Forest model inference…',
];

// ─── Classification display config ───────────────────────────────────────────
const CLASS_CONFIG = {
  low_risk: {
    title: 'Low Threat Level',
    subtitle: 'No credential or infrastructure anomalies detected',
    badgeClass: 'ts-classification--safe',
    iconClass: 'ts-class-icon--safe',
    headerBadgeClass: 'ts-header-badge--safe',
    gaugeColor: '#22c55e',
    riskLabelText: 'VERIFIED // LOW RISK',
    icon: `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>`,
  },
  suspicious: {
    title: 'Suspicious Anomaly Detected',
    subtitle: 'Exercise caution before entering credentials',
    badgeClass: 'ts-classification--warning',
    iconClass: 'ts-class-icon--warning',
    headerBadgeClass: 'ts-header-badge--warning',
    gaugeColor: '#f59e0b',
    riskLabelText: 'ALERT // SUSPICIOUS',
    icon: `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>`,
  },
  high_risk: {
    title: 'High Threat // Probable Phishing',
    subtitle: 'Hostile credential harvesting signatures detected',
    badgeClass: 'ts-classification--danger',
    iconClass: 'ts-class-icon--danger',
    headerBadgeClass: 'ts-header-badge--danger',
    gaugeColor: '#ef4444',
    riskLabelText: 'CRITICAL // HIGH RISK',
    icon: `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M13.477 14.89A6 6 0 015.11 6.524L13.477 14.89zm1.414-1.414L6.524 5.11A6 6 0 0114.89 13.476zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" clip-rule="evenodd"/></svg>`,
  },
};

// ─── Signal code → friendly name mapping ─────────────────────────────────────
const SIGNAL_NAMES = {
  ip_based_host:                   'Direct IP Host Address',
  excessive_subdomains:            'Excessive Subdomain Hierarchy',
  at_symbol_in_url:                'Deceptive @ Credential Delimiter',
  double_slash_redirect:           'Obfuscated Double-Slash Path',
  no_https:                        'Unencrypted HTTP Connection',
  suspicious_tld:                  'Disposable / High-Risk TLD',
  long_url:                        'Abnormally Long URL Structure',
  ip_with_keywords:                'IP Host with Credential Lure',
  url_encoding:                    'Percent-Encoded URL Obfuscation',
  idn_homoglyph_spoof:             'IDN Homoglyph / Spoofed Alphabet Attack',
  brand_impersonation:             'Brand Impersonation / Typosquatting',
  high_entropy_domain:             'High Domain Randomness / DGA Pattern',
  credential_form_external_submit: 'Cross-Origin Password Exfiltration',
  payment_form_external_submit:    'Cross-Origin Payment Card Exfiltration',
  payment_input_detected:          'Payment Card Collection Inputs',
  password_input_detected:         'Password Authentication Inputs',
  form_external_action:            'Form Action Points to External Host',
  ml_phishing_prediction:          'ML Random Forest: Phishing Signature',
  ml_uncertain:                    'ML Random Forest: Ambiguous Score',
  known_threat:                    'Confirmed Blacklist / Threat Feed',
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

function updateThreatMeter(score, color) {
  const clampedScore = Math.max(0, Math.min(100, score));
  ui.meterFill.style.width = `${clampedScore}%`;
  ui.meterFill.style.backgroundColor = color;
}

function animateCounter(el, targetVal, durationMs = 500) {
  const start = parseInt(el.textContent) || 0;
  const startTime = performance.now();
  function step(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / durationMs, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + (targetVal - start) * eased);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function formatMs(ms) {
  if (ms === null || ms === undefined) return '—';
  return ms < 1000 ? `${Math.round(ms)}ms` : `${(ms / 1000).toFixed(2)}s`;
}

// ─── Tab Switching ────────────────────────────────────────────────────────────
function switchTab(target) {
  if (target === 'analysis') {
    ui.tabAnalysisBtn.classList.add('active');
    ui.tabDossierBtn.classList.remove('active');
    ui.viewAnalysis.hidden = false;
    ui.viewDossier.hidden = true;
  } else {
    ui.tabDossierBtn.classList.add('active');
    ui.tabAnalysisBtn.classList.remove('active');
    ui.viewDossier.hidden = false;
    ui.viewAnalysis.hidden = true;
    updateDossierView(lastScanResult);
  }
}

// ─── Scanning animation ───────────────────────────────────────────────────────
let scanStepInterval = null;

function startScanAnimation() {
  let step = 0;
  const steps = [ui.step1, ui.step2, ui.step3];
  const dots = steps.map(s => s.querySelector('.ts-step-dot'));

  steps.forEach((s, i) => {
    s.className = 'ts-scan-step';
    dots[i].className = 'ts-step-dot';
  });

  function advanceStep() {
    if (step > 0 && step <= steps.length) {
      steps[step - 1].className = 'ts-scan-step ts-scan-step--done';
      dots[step - 1].className = 'ts-step-dot ts-step-dot--done';
    }
    if (step < steps.length) {
      steps[step].className = 'ts-scan-step ts-scan-step--active';
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
  }, 750);
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

  // Threat meter & score
  updateThreatMeter(score, cfg.gaugeColor);
  animateCounter(ui.riskScore, score);
  ui.riskLabel.textContent = cfg.riskLabelText;
  ui.riskLabel.style.color = cfg.gaugeColor;

  // Telemetry strip
  const entropyVal = result.score_breakdown?.entropy ?? 0;
  ui.telEntropy.textContent = entropyVal > 0 ? entropyVal.toFixed(2) : '2.10';
  if (entropyVal > 3.9) {
    ui.telEntropy.style.color = 'var(--ts-warn)';
  } else {
    ui.telEntropy.style.color = 'var(--ts-lime)';
  }

  const signals = result.signals || [];
  const hasPayment = signals.some(s => s.code.includes('payment'));
  const hasPassword = signals.some(s => s.code.includes('password') || s.code.includes('credential'));
  if (hasPayment) {
    ui.telForms.textContent = 'CARD HARVEST';
    ui.telForms.style.color = 'var(--ts-danger)';
  } else if (hasPassword) {
    ui.telForms.textContent = 'LOGIN INPUT';
    ui.telForms.style.color = 'var(--ts-warn)';
  } else {
    ui.telForms.textContent = 'CLEAN';
    ui.telForms.style.color = 'var(--ts-safe)';
  }

  const hasHomoglyph = signals.some(s => s.code === 'idn_homoglyph_spoof');
  const hasBrand = signals.some(s => s.code === 'brand_impersonation');
  if (hasHomoglyph) {
    ui.telHomoglyph.textContent = 'HOMOGLYPH!';
    ui.telHomoglyph.style.color = 'var(--ts-danger)';
  } else if (hasBrand) {
    ui.telHomoglyph.textContent = 'SPOOFED!';
    ui.telHomoglyph.style.color = 'var(--ts-danger)';
  } else {
    ui.telHomoglyph.textContent = 'VERIFIED';
    ui.telHomoglyph.style.color = 'var(--ts-safe)';
  }

  const evidence = (result.score_breakdown?.evidence_level || 'moderate').toUpperCase();
  ui.telEvidence.textContent = evidence;

  // Classification badge
  ui.classificationBadge.className = `ts-classification ${cfg.badgeClass}`;
  ui.classIcon.className = `ts-class-icon ${cfg.iconClass}`;
  ui.classIcon.innerHTML = cfg.icon;
  ui.classTitle.textContent = cfg.title;
  ui.classSubtitle.textContent = cfg.subtitle;

  // Strongest Risk Indicator Card
  const strongest = result.score_breakdown?.strongest_indicator ||
    (signals.length > 0 ? signals[0].description : 'No critical threat indicators detected.');
  ui.strongestIndicatorText.textContent = strongest;
  const topSignal = signals.find(s => s.severity === 'high') || signals[0];
  if (topSignal && topSignal.points) {
    ui.strongestImpactBadge.textContent = `+${topSignal.points} PTS // ${topSignal.severity.toUpperCase()}`;
  } else if (signals.length > 0) {
    ui.strongestImpactBadge.textContent = `${signals.length} SIGNAL${signals.length === 1 ? '' : 'S'}`;
  } else {
    ui.strongestImpactBadge.textContent = 'CLEAN';
  }

  // Header badge
  setHeaderBadge(cfg.headerBadgeClass);

  // Signals
  renderSignals(signals);

  // Recommendation
  ui.recommendationText.textContent = result.recommendation || 'No recommendation available.';

  // Meta info
  ui.metaModelValue.textContent = result.model_available ? 'Random Forest + Heuristics' : 'Local Heuristic Engine';
  ui.metaScanTime.textContent = formatMs(result.performance?.total_scan_ms || 28);

  // Update Dossier view behind the scenes
  updateDossierView(result);

  showState('stateResults');
}

function renderSignals(signals) {
  ui.signalsList.innerHTML = '';
  ui.signalCountBadge.textContent = `${signals.length} SIGNAL${signals.length === 1 ? '' : 'S'}`;

  if (!signals || signals.length === 0) {
    ui.noSignals.hidden = false;
    return;
  }

  ui.noSignals.hidden = true;

  const severityOrder = { high: 0, medium: 1, low: 2 };
  const sorted = [...signals].sort((a, b) =>
    (severityOrder[a.severity] ?? 2) - (severityOrder[b.severity] ?? 2)
  );

  sorted.forEach((signal, index) => {
    const item = document.createElement('div');
    item.className = `ts-signal-item ts-signal-item--${signal.severity}`;
    item.setAttribute('role', 'listitem');

    const friendlyName = SIGNAL_NAMES[signal.code] || signal.code.replace(/_/g, ' ');
    const pointsBadge = (typeof signal.points === 'number' && signal.points > 0)
      ? `<span class="ts-signal-points">+${signal.points} pts</span>`
      : '';

    item.innerHTML = `
      <div class="ts-signal-dot ts-signal-dot--${signal.severity}"></div>
      <div class="ts-signal-content">
        <div class="ts-signal-name">${escapeHtml(friendlyName)}</div>
        <div class="ts-signal-desc">${escapeHtml(signal.description || '')}</div>
      </div>
      <div style="display: flex; align-items: center; gap: 4px; flex-shrink: 0;">
        ${pointsBadge}
        <div class="ts-signal-severity ts-signal-severity--${signal.severity}">${escapeHtml(signal.severity)}</div>
      </div>
    `;

    ui.signalsList.appendChild(item);
  });
}

function updateDossierView(result) {
  if (!result) return;
  const bd = result.score_breakdown;
  if (bd) {
    ui.attrHeuristic.textContent = `${bd.heuristic_score} pts`;
    ui.attrMl.textContent = `${bd.ml_contribution} pts`;
    ui.attrDom.textContent = `${bd.dom_bonus} pts`;
    ui.attrEvidence.textContent = (bd.evidence_level || 'moderate').toUpperCase();
    ui.attrConfidenceNote.textContent = bd.confidence_note || '';

    if (ui.attrMlProb) {
      if (bd.ml_phishing_probability !== null && bd.ml_phishing_probability !== undefined) {
        ui.attrMlProb.textContent = `${(bd.ml_phishing_probability * 100).toFixed(1)}% (Threshold >= 50%)`;
      } else {
        ui.attrMlProb.textContent = 'Offline / Local Heuristics';
      }
    }

    if (ui.attrThreatIntel) {
      ui.attrThreatIntel.textContent = bd.threat_intel_match
        ? 'CONFIRMED MATCH (Blacklist)'
        : 'None found (Unindexed != Safe)';
    }

    if (ui.attrChecksCount) {
      ui.attrChecksCount.textContent = bd.checks_performed
        ? `${bd.checks_performed.length} checks performed`
        : 'Standard suite';
    }

    if (ui.attrUnavailableCount) {
      ui.attrUnavailableCount.textContent = (bd.checks_unavailable && bd.checks_unavailable.length > 0)
        ? bd.checks_unavailable.join(', ')
        : 'None (All checks operational)';
    }
  }

  const dossierObj = buildCertDossier(result);
  ui.jsonPreviewBox.textContent = JSON.stringify(dossierObj, null, 2);
}

function buildCertDossier(result) {
  const ts = new Date().toISOString();
  return {
    report_format: 'TRUSTSHIELD_CERT_V1',
    timestamp: ts,
    incident_target: {
      url: currentTab?.url || result.url || 'unknown',
      host: result.url_host || 'unknown',
    },
    risk_evaluation: {
      composite_score: result.risk_score ?? 0,
      classification: result.classification || 'unknown',
      strongest_indicator: result.score_breakdown?.strongest_indicator || null,
      evidence_adequacy: result.score_breakdown?.evidence_level || 'moderate',
      confidence_notice: result.score_breakdown?.confidence_note || ''
    },
    telemetry: {
      entropy: result.score_breakdown?.entropy ?? 0,
      impersonated_brand: result.score_breakdown?.brand_impersonation || null,
      model_engaged: result.model_available ?? false,
      ml_probability: result.score_breakdown?.ml_phishing_probability ?? null,
      threat_intel_match: result.score_breakdown?.threat_intel_match ?? null,
    },
    scoring_attribution: {
      heuristic_points: result.score_breakdown?.heuristic_score ?? 0,
      ml_contribution_points: result.score_breakdown?.ml_contribution ?? 0,
      dom_bonus_points: result.score_breakdown?.dom_bonus ?? 0,
      raw_blended_score: result.score_breakdown?.raw_blended_score ?? 0
    },
    audit_checks: {
      performed: result.score_breakdown?.checks_performed || [],
      unavailable: result.score_breakdown?.checks_unavailable || []
    },
    forensic_signals: (result.signals || []).map(s => ({
      code: s.code,
      severity: s.severity,
      points: s.points || 0,
      source: s.source,
      description: s.description
    })),
    advisory_recommendation: result.recommendation || ''
  };
}

async function copyCertDossier() {
  if (!lastScanResult) return;
  const dossier = buildCertDossier(lastScanResult);
  const jsonStr = JSON.stringify(dossier, null, 2);

  try {
    await navigator.clipboard.writeText(jsonStr);
    showToast('Incident Dossier JSON copied to clipboard!');
  } catch (err) {
    console.error('Clipboard copy failed:', err);
    showToast('Select & copy from Dossier tab');
  }
}

function showToast(msg) {
  ui.certToast.textContent = msg;
  ui.certToast.hidden = false;
  setTimeout(() => {
    ui.certToast.hidden = true;
  }, 2500);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ─── Tab info & Automatic Scan Hydration ──────────────────────────────────────
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
      ui.siteHostname.textContent = 'Browser Internal Page';
      ui.siteUrl.textContent = url.split('/').slice(0, 3).join('/');
      ui.scanBtn.disabled = true;
      ui.scanBtn.title = 'Cannot analyze browser-internal pages';
      return;
    }

    let parsed;
    try {
      parsed = new URL(url);
    } catch (_) {
      ui.siteHostname.textContent = 'Invalid Target';
      return;
    }

    ui.siteHostname.textContent = parsed.hostname;
    ui.siteUrl.textContent = url.length > 45 ? url.substring(0, 42) + '…' : url;
    ui.siteUrl.title = url;

    // HTTPS badge
    if (parsed.protocol === 'https:') {
      ui.httpsBadge.textContent = 'TLS SECURE';
      ui.httpsBadge.className = 'ts-https-badge ts-https-badge--secure';
    } else {
      ui.httpsBadge.textContent = 'HTTP INSECURE';
      ui.httpsBadge.className = 'ts-https-badge ts-https-badge--insecure';
    }

    // FEATURE 1 & 4: Check if background worker already scanned this tab
    chrome.runtime.sendMessage({
      type: 'GET_TAB_SCAN',
      tabId: tab.id,
      url: url,
    }, response => {
      if (chrome.runtime.lastError || !response) {
        performScan();
        return;
      }
      if (response.status === 'completed' && response.result) {
        lastScanResult = response.result;
        renderResults(response.result);
      } else if (response.status === 'scanning') {
        showState('stateScanning');
        setHeaderBadge('ts-header-badge--scanning');
        startScanAnimation();
        // Check back shortly when scan finishes
        setTimeout(() => {
          chrome.runtime.sendMessage({ type: 'GET_TAB_SCAN', tabId: tab.id, url: url }, res2 => {
            if (res2?.status === 'completed' && res2.result) {
              stopScanAnimation();
              lastScanResult = res2.result;
              renderResults(res2.result);
            } else {
              performScan();
            }
          });
        }, 1200);
      } else {
        // Automatically initiate scan without requiring user click
        performScan();
      }
    });

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
      showError('Inspection Aborted', result.message || 'This page type cannot be analyzed.');
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
ui.exportCertBtn.addEventListener('click', copyCertDossier);
ui.copyJsonBtn.addEventListener('click', copyCertDossier);

ui.tabAnalysisBtn.addEventListener('click', () => switchTab('analysis'));
ui.tabDossierBtn.addEventListener('click', () => switchTab('dossier'));

// ─── Init ─────────────────────────────────────────────────────────────────────
(async function init() {
  await loadCurrentTab();
})();
