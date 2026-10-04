/**
 * SCAMSHIELD: Frontend Application Logic
 * AI-Powered Scam & Phishing Risk Analyzer
 */

// Application State
const state = {
  currentChannel: "Unknown",
  currentAnalysis: null,
  sampleCases: [],
  history: [],
  apiKey: localStorage.getItem("scamshield_api_key") || ""
};

// DOM Elements
const elements = {
  inputText: document.getElementById("input-text"),
  inputSender: document.getElementById("input-sender"),
  btnAnalyze: document.getElementById("btn-analyze"),
  btnPaste: document.getElementById("btn-paste"),
  btnClear: document.getElementById("btn-clear"),
  charCounter: document.getElementById("char-counter"),
  wordCounter: document.getElementById("word-counter"),
  channelSelector: document.getElementById("channel-selector"),
  
  // Scanning state
  scanningIndicator: document.getElementById("scanning-indicator"),
  scanningStepText: document.getElementById("scanning-step-text"),
  
  // Results
  resultsSection: document.getElementById("results-section"),
  gaugeProgress: document.getElementById("gauge-progress"),
  resultScoreNumber: document.getElementById("result-score-number"),
  resultRiskLevelBadge: document.getElementById("result-risk-level-badge"),
  resultCategoryBadge: document.getElementById("result-category-badge"),
  resultConfidenceText: document.getElementById("result-confidence-text"),
  resultEngineText: document.getElementById("result-engine-text"),
  resultSummaryText: document.getElementById("result-summary-text"),
  messageHeatmapContainer: document.getElementById("message-heatmap-container"),
  whyFlaggedContainer: document.getElementById("why-flagged-container"),
  redFlagsContainer: document.getElementById("red-flags-container"),
  extractedEntitiesContainer: document.getElementById("extracted-entities-container"),
  recommendedActionsContainer: document.getElementById("recommended-actions-container"),
  btnCopyReport: document.getElementById("btn-copy-report"),
  
  // History Drawer
  btnOpenHistory: document.getElementById("btn-open-history"),
  btnCloseHistory: document.getElementById("btn-close-history"),
  historyDrawer: document.getElementById("history-drawer"),
  historyBackdrop: document.getElementById("history-drawer-backdrop"),
  historyListContainer: document.getElementById("history-list-container"),
  historyCounterBadge: document.getElementById("history-counter-badge"),
  btnClearHistory: document.getElementById("btn-clear-history"),
  
  // Settings Modal
  btnOpenSettings: document.getElementById("btn-open-settings"),
  btnCloseSettings: document.getElementById("btn-close-settings"),
  settingsModal: document.getElementById("settings-modal"),
  inputApiKey: document.getElementById("input-api-key"),
  btnSaveSettings: document.getElementById("btn-save-settings"),
  
  // Top Navigation Pill
  navEnginePill: document.getElementById("nav-engine-pill"),
  navEngineText: document.getElementById("nav-engine-text"),
  
  // Toast
  toast: document.getElementById("toast"),
  toastMessage: document.getElementById("toast-message")
};

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
  initIcons();
  loadServerStatus();
  loadSampleCases();
  loadHistoryFromStorage();
  setupEventListeners();
  updateTextCounts();
});

function initIcons() {
  if (window.lucide) {
    lucide.createIcons();
  }
}

// Show Toast Message
function showToast(message, isError = false) {
  if (!elements.toast) return;
  elements.toastMessage.textContent = message;
  
  const icon = document.getElementById("toast-icon");
  if (icon) {
    icon.setAttribute("data-lucide", isError ? "alert-triangle" : "check-circle");
    icon.className = `w-4 h-4 ${isError ? "text-rose-400" : "text-emerald-400"}`;
    initIcons();
  }

  elements.toast.classList.remove("translate-y-20", "opacity-0", "pointer-events-none");
  setTimeout(() => {
    elements.toast.classList.add("translate-y-20", "opacity-0", "pointer-events-none");
  }, 3200);
}

//  Server Status
async function loadServerStatus() {
  try {
    const res = await fetch("/api/status");
    if (res.ok) {
      const data = await res.json();
      if (elements.navEngineText) {
        elements.navEngineText.textContent = data.activeEngine || "Defense Engine Active";
      }
    }
  } catch (err) {
    console.warn("Could not check server status:", err);
  }
}
etch
// Fetch Sample Cases
async function loadSampleCases() {
  try {
    const res = await fetch("/api/sample-cases");
    if (res.ok) {
      const data = await res.json();
      state.sampleCases = data.cases || [];
    }
  } catch (err) {
    console.warn("Could not load sample cases from API:", err);
  }
}

// Setup Event Listeners
function setupEventListeners() {
  // Input changes
  elements.inputText.addEventListener("input", updateTextCounts);
  
  // Keyboard Shortcut: Ctrl + Enter
  elements.inputText.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      handleAnalyze();
    }
  });

  // Paste button
  elements.btnPaste.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        elements.inputText.value = text;
        updateTextCounts();
        showToast("Text pasted from clipboard");
      }
    } catch (err) {
      elements.inputText.focus();
      showToast("Please use Ctrl+V to paste", true);
    }
  });

  // Clear button
  elements.btnClear.addEventListener("click", () => {
    elements.inputText.value = "";
    elements.inputSender.value = "";
    updateTextCounts();
    elements.inputText.focus();
  });

  // Channel Buttons
  if (elements.channelSelector) {
    elements.channelSelector.querySelectorAll(".channel-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        elements.channelSelector.querySelectorAll(".channel-btn").forEach(b => {
          b.classList.remove("text-white", "bg-slate-800");
          b.classList.add("text-slate-400");
        });
        btn.classList.add("text-white", "bg-slate-800");
        btn.classList.remove("text-slate-400");
        state.currentChannel = btn.dataset.channel || "Unknown";
      });
    });
  }

  // Sample Buttons
  document.querySelectorAll(".sample-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const sampleId = btn.dataset.sample;
      loadSampleById(sampleId);
    });
  });

  // Primary Analyze CTA
  elements.btnAnalyze.addEventListener("click", handleAnalyze);

  // Copy Incident Report
  elements.btnCopyReport.addEventListener("click", copyIncidentReport);

  // History Drawer Toggles
  elements.btnOpenHistory.addEventListener("click", openHistoryDrawer);
  elements.btnCloseHistory.addEventListener("click", closeHistoryDrawer);
  elements.historyBackdrop.addEventListener("click", closeHistoryDrawer);
  elements.btnClearHistory.addEventListener("click", clearHistory);

  // Settings Modal Toggles
  elements.btnOpenSettings.addEventListener("click", openSettingsModal);
  elements.btnCloseSettings.addEventListener("click", closeSettingsModal);
  elements.btnSaveSettings.addEventListener("click", saveSettings);
}

// Update Word and Char Counts
function updateTextCounts() {
  const text = elements.inputText.value || "";
  elements.charCounter.textContent = `${text.length} characters`;
  
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  elements.wordCounter.textContent = `${words} words`;
}

// Load Sample Message by ID
function loadSampleById(id) {
  const sample = state.sampleCases.find(c => c.id === id);
  if (!sample) return;

  elements.inputText.value = sample.text;
  if (sample.sender) {
    elements.inputSender.value = sample.sender;
  }
  
  // Set channel button
  if (sample.channel && elements.channelSelector) {
    elements.channelSelector.querySelectorAll(".channel-btn").forEach(b => {
      if (b.dataset.channel.toLowerCase() === sample.channel.toLowerCase()) {
        b.click();
      }
    });
  }F

  updateTextCounts();
  showToast(`Loaded sample: "${sample.title}"`);
  
  // Highlight analyze CTA
  elements.btnAnalyze.scrollIntoView({ behavior: "smooth", block: "center" });
}

// Main Analyze Flow
async function handleAnalyze() {
  const text = elements.inputText.value.trim();
  if (!text) {
    showToast("Please paste or type a message to analyze.", true);
    elements.inputText.focus();
    return;
  }

  const sender = elements.inputSender.value.trim() || null;
  const channel = state.currentChannel;
  const apiKey = state.apiKey || null;

  // Show Radar Scanning State
  elements.resultsSection.classList.add("hidden");
  elements.scanningIndicator.classList.remove("hidden");
  elements.scanningIndicator.scrollIntoView({ behavior: "smooth", block: "center" });

  const steps = [
    "Deconstructing social engineering vectors...",
    "Inspecting domain heuristics & lookalike targets...",
    "Scanning for inverted UPI payment traps...",
    "Synthesizing forensic explainability matrix..."
  ];

  let stepIdx = 0;
  const stepInterval = setInterval(() => {
    stepIdx = (stepIdx + 1) % steps.length;
    elements.scanningStepText.textContent = steps[stepIdx];
  }, 500);

  try {
    const payload = { text, sender, channel, apiKey };
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    clearInterval(stepInterval);

    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }

    const result = await response.json();
    state.currentAnalysis = result;

    // Render results
    renderResults(result, text);

    // Save to history
    saveToHistory(result, text);

  } catch (err) {
    clearInterval(stepInterval);
    console.error("Analysis error:", err);
    showToast("Analysis encountered an issue. Using local fallback engine.", true);
  } finally {
    elements.scanningIndicator.classList.add("hidden");
  }
}

// Render Results Dashboard
function renderResults(data, originalText) {
  elements.resultsSection.classList.remove("hidden");
  elements.resultsSection.style.opacity = "0";

  // 1. Risk Score Gauge & Number
  const score = Math.max(0, Math.min(100, data.riskScore || 0));
  animateScoreNumber(score);
  setGaugeProgress(score, data.riskLevel);

  // 2. Risk Level Badge
  elements.resultRiskLevelBadge.className = `px-3.5 py-1 rounded-full text-xs font-extrabold tracking-wider uppercase ${getRiskBadgeClass(data.riskLevel)}`;
  elements.resultRiskLevelBadge.textContent = `${data.riskLevel} RISK ${data.riskLevel === 'SAFE' ? '' : 'THREAT'}`;

  // 3. Category & Confidence & Engine
  elements.resultCategoryBadge.textContent = data.category || "Social Engineering";
  elements.resultConfidenceText.textContent = `${Math.round((data.confidence || 0.9) * 100)}% Confidence`;
  elements.resultEngineText.textContent = data.engineUsed || "Heuristic Defense Engine";

  // 4. Executive Summary
  elements.resultSummaryText.textContent = data.summary || "No summary available.";

  // 5. Interactive Message Heatmap
  renderMessageHeatmap(originalText, data.detectedPhrases || [], data.redFlags || []);

  // 6. Why Flagged Factor Cards
  renderWhyFlagged(data.whyFlagged || []);

  // 7. Red Flags Gallery
  renderRedFlags(data.redFlags || []);

  // 8. Extracted Entities
  renderExtractedEntities(data.extractedEntities || {});

  // 9. Recommended Actions Checklist
  renderRecommendedActions(data.recommendedActions || []);

  // Reinitialize icons
  initIcons();

  // Smooth fade-in and scroll
  setTimeout(() => {
    elements.resultsSection.style.opacity = "1";
    elements.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 50);
}

// Animate Score Counter
function animateScoreNumber(target) {
  let current = 0;
  const duration = 1200;
  const start = performance.now();

  function update(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // Ease-out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    current = Math.round(eased * target);
    elements.resultScoreNumber.textContent = current;

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }
  requestAnimationFrame(update);
}

// Set Radial SVG Gauge
function setGaugeProgress(score, riskLevel) {
  const circumference = 2 * Math.PI * 50; // r=50 => ~314.159
  const offset = circumference - (score / 100) * circumference;
  
  let strokeColor = "#EF4444";
  if (riskLevel === "CRITICAL") strokeColor = "#F43F5E";
  else if (riskLevel === "HIGH") strokeColor = "#EF4444";
  else if (riskLevel === "MEDIUM") strokeColor = "#F59E0B";
  else if (riskLevel === "LOW") strokeColor = "#06B6D4";
  else if (riskLevel === "SAFE") strokeColor = "#10B981";

  elements.gaugeProgress.style.stroke = strokeColor;
  elements.gaugeProgress.style.strokeDashoffset = offset;
}

// Get Badge Class based on level
function getRiskBadgeClass(level) {
  switch (level) {
    case "CRITICAL": return "risk-badge-critical";
    case "HIGH": return "risk-badge-high";
    case "MEDIUM": return "risk-badge-medium";
    case "LOW": return "risk-badge-low";
    case "SAFE": return "risk-badge-safe";
    default: return "risk-badge-high";
  }
}

// Render Interactive Message Heatmap
function renderMessageHeatmap(rawText, detectedPhrases, redFlags) {
  const container = elements.messageHeatmapContainer;
  container.innerHTML = "";

  // Combine phrases from both detectedPhrases and redFlags quotes
  const phrasesToHighlight = [];

  detectedPhrases.forEach(dp => {
    if (dp.phrase && dp.phrase.trim().length > 3) {
      phrasesToHighlight.push({
        phrase: dp.phrase.trim(),
        reason: dp.reason || "Suspicious threat trigger",
        severity: (dp.severity || "HIGH").toLowerCase()
      });
    }
  });

  redFlags.forEach(rf => {
    if (rf.quote && rf.quote.trim().length > 3) {
      if (!phrasesToHighlight.some(p => p.phrase.toLowerCase() === rf.quote.trim().toLowerCase())) {
        phrasesToHighlight.push({
          phrase: rf.quote.trim(),
          reason: rf.description || rf.title,
          severity: (rf.severity || "HIGH").toLowerCase()
        });
      }
    }
  });

  if (phrasesToHighlight.length === 0) {
    container.textContent = rawText;
    return;
  }

  // Sort phrases by descending length to prevent partial sub-matching issues
  phrasesToHighlight.sort((a, b) => b.phrase.length - a.phrase.length);

  let html = escapeHtml(rawText);

  phrasesToHighlight.forEach(item => {
    const escapedPhrase = escapeHtml(item.phrase);
    // Regex replace case-insensitive
    const regex = new RegExp(`(${escapeRegExp(escapedPhrase)})`, 'gi');
    html = html.replace(regex, (match) => {
      return `<span class="highlight-threat ${item.severity}">
        ${match}
        <span class="threat-tooltip font-sans">
          <strong>⚠️ Flagged Trigger:</strong><br>${escapeHtml(item.reason)}
        </span>
      </span>`;
    });
  });

  container.innerHTML = html;
}

// Render "Why Was This Flagged?" Cards
function renderWhyFlagged(whyList) {
  const container = elements.whyFlaggedContainer;
  container.innerHTML = "";

  if (!whyList || whyList.length === 0) {
    container.innerHTML = `
      <div class="col-span-full p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400">
        No severe threat vectors detected. The message follows standard communication patterns.
      </div>
    `;
    return;
  }

  whyList.forEach(item => {
    const card = document.createElement("div");
    card.className = "p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition space-y-2.5";
    card.innerHTML = `
      <div class="flex items-center space-x-2">
        <span class="w-2 h-2 rounded-full bg-rose-400"></span>
        <h4 class="text-xs font-bold uppercase tracking-wider text-slate-200">${escapeHtml(item.factor)}</h4>
      </div>
      <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(item.explanation)}</p>
      ${item.detectedQuote ? `
        <div class="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-amber-300/90 flex items-start space-x-1.5">
          <span class="text-slate-500 flex-shrink-0">"</span>
          <span class="italic">${escapeHtml(item.detectedQuote)}</span>
          <span class="text-slate-500 flex-shrink-0">"</span>
        </div>
      ` : ''}
    `;
    container.appendChild(card);
  });
}

// Render Red Flags Gallery
function renderRedFlags(flags) {
  const container = elements.redFlagsContainer;
  container.innerHTML = "";

  if (!flags || flags.length === 0) {
    container.innerHTML = `
      <div class="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-emerald-400 flex items-center space-x-2">
        <i data-lucide="check-circle" class="w-4 h-4"></i>
        <span>No critical red flags detected in this text.</span>
      </div>
    `;
    return;
  }

  flags.forEach(flag => {
    const severity = flag.severity || "HIGH";
    let badgeClass = "bg-rose-500/10 text-rose-400 border-rose-500/30";
    if (severity === "MEDIUM") badgeClass = "bg-amber-500/10 text-amber-400 border-amber-500/30";
    if (severity === "LOW") badgeClass = "bg-sky-500/10 text-sky-400 border-sky-500/30";

    const item = document.createElement("div");
    item.className = "p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700/80 transition space-y-1.5";
    item.innerHTML = `
      <div class="flex items-center justify-between">
        <span class="text-xs font-bold text-slate-200 flex items-center space-x-1.5">
          <span>🚩</span>
          <span>${escapeHtml(flag.title)}</span>
        </span>
        <span class="px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border ${badgeClass}">${severity}</span>
      </div>
      <p class="text-xs text-slate-400 leading-relaxed">${escapeHtml(flag.description)}</p>
      ${flag.quote ? `
        <p class="text-[11px] font-mono text-slate-500 italic">Evidence: "${escapeHtml(flag.quote)}"</p>
      ` : ''}
    `;
    container.appendChild(item);
  });
}

// Render Extracted Entities
function renderExtractedEntities(entities) {
  const container = elements.extractedEntitiesContainer;
  container.innerHTML = "";

  const urls = entities.urls || [];
  const phones = entities.phoneNumbers || [];
  const amounts = entities.monetaryAmounts || [];
  const brand = entities.impersonatedEntity;
  const domains = entities.suspiciousDomains || [];

  let hasData = false;

  // Impersonated Entity
  if (brand) {
    hasData = true;
    container.innerHTML += `
      <div class="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
        <span class="text-slate-400 font-semibold uppercase text-[10px] tracking-wider">Impersonation Target:</span>
        <p class="text-rose-300 font-bold text-xs">${escapeHtml(brand)}</p>
      </div>
    `;
  }

  // URLs & Domains
  if (urls.length > 0) {
    hasData = true;
    let urlHtml = `
      <div class="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-2">
        <span class="text-slate-400 font-semibold uppercase text-[10px] tracking-wider">Extracted Links & Threat Assessment:</span>
        <div class="space-y-1.5">
    `;
    urls.forEach((u, i) => {
      const dReport = domains[i] || {};
      const isRisky = (dReport.risk_points || 0) > 0;
      urlHtml += `
        <div class="p-2 rounded bg-slate-950 border border-slate-800/80 space-y-1">
          <div class="flex items-center justify-between">
            <span class="font-mono text-[11px] text-sky-400 truncate max-w-[240px]">${escapeHtml(u)}</span>
            <span class="px-1.5 py-0.2 rounded text-[9px] font-bold ${isRisky ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-emerald-500/20 text-emerald-300'}">
              ${isRisky ? 'SUSPICIOUS LINK' : 'CLEAN DOMAIN'}
            </span>
          </div>
          ${dReport.reasons && dReport.reasons.length > 0 ? `
            <p class="text-[10px] text-rose-400/90">${escapeHtml(dReport.reasons.join("; "))}</p>
          ` : ''}
        </div>
      `;
    });
    urlHtml += `</div></div>`;
    container.innerHTML += urlHtml;
  }

  // Financial Triggers
  if (amounts.length > 0) {
    hasData = true;
    container.innerHTML += `
      <div class="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
        <span class="text-slate-400 font-semibold uppercase text-[10px] tracking-wider">Financial Amounts Cited:</span>
        <div class="flex flex-wrap gap-1.5 pt-0.5">
          ${amounts.map(a => `<span class="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 text-xs font-mono">${escapeHtml(a)}</span>`).join('')}
        </div>
      </div>
    `;
  }

  // Phone Numbers
  if (phones.length > 0) {
    hasData = true;
    container.innerHTML += `
      <div class="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
        <span class="text-slate-400 font-semibold uppercase text-[10px] tracking-wider">Contact Numbers:</span>
        <div class="flex flex-wrap gap-1.5 pt-0.5">
          ${phones.map(p => `<span class="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-xs">${escapeHtml(p)}</span>`).join('')}
        </div>
      </div>
    `;
  }

  if (!hasData) {
    container.innerHTML = `
      <div class="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-500">
        No external links, financial bait numbers, or specific brand targets detected.
      </div>
    `;
  }
}

// Render Recommended Actions Checklist
function renderRecommendedActions(actions) {
  const container = elements.recommendedActionsContainer;
  container.innerHTML = "";

  if (!actions || actions.length === 0) {
    container.innerHTML = `<p class="text-xs text-slate-400">No actions needed.</p>`;
    return;
  }

  actions.forEach((act, idx) => {
    const id = `action-check-${idx}`;
    const row = document.createElement("div");
    row.className = "flex items-start space-x-3 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 hover:bg-slate-900 transition";
    row.innerHTML = `
      <input type="checkbox" id="${id}" class="action-checkbox mt-1 w-4 h-4 rounded bg-slate-950 border-slate-700 text-emerald-500 focus:ring-emerald-500 cursor-pointer">
      <label for="${id}" class="text-xs text-slate-200 cursor-pointer select-none leading-relaxed flex-1">
        ${escapeHtml(act)}
      </label>
    `;
    container.appendChild(row);
  });
}

// Generate & Copy Forensic Incident Report
function copyIncidentReport() {
  if (!state.currentAnalysis) {
    showToast("No active analysis to copy.", true);
    return;
  }

  const d = state.currentAnalysis;
  const original = elements.inputText.value.trim();
  const dateStr = new Date().toLocaleString();

  const report = [
    `=============================================================`,
    `SCAMSHIELD FORENSIC INCIDENT REPORT`,
    `Official Security & Risk Analysis Summary`,
    `Generated: ${dateStr}`,
    `=============================================================`,
    ``,
    `THREAT METRICS:`,
    `* Risk Assessment : ${d.riskLevel} (${d.riskScore}/100 Risk Score)`,
    `* Scam Category   : ${d.category}`,
    `* AI Confidence   : ${Math.round((d.confidence || 0.9) * 100)}%`,
    `* Detection Engine: ${d.engineUsed}`,
    ``,
    `EXECUTIVE SUMMARY:`,
    `${d.summary}`,
    ``,
    `SUSPICIOUS MESSAGE EVIDENCE:`,
    `"""`,
    `${original}`,
    `"""`,
    ``,
    `PRIMARY RED FLAGS:`,
    ...(d.redFlags || []).map(rf => `[${rf.severity}] ${rf.title}: ${rf.description} ${rf.quote ? `(Quote: "${rf.quote}")` : ''}`),
    ``,
    `EXPLAINABILITY (WHY FLAGGED):`,
    ...(d.whyFlagged || []).map(wf => `* ${wf.factor}: ${wf.explanation}`),
    ``,
    `RECOMMENDED SAFETY ACTIONS:`,
    ...(d.recommendedActions || []).map((ra, i) => `${i + 1}. ${ra}`),
    ``,
    `=============================================================`,
    `Reported via ScamShield (Think before you click.)`,
    `Emergency Cyber Helpline: Dial 1930 (India) or cybercrime.gov.in`,
    `=============================================================`
  ].join("\n");

  navigator.clipboard.writeText(report).then(() => {
    showToast("Forensic incident report copied to clipboard!");
  }).catch(() => {
    showToast("Failed to copy report to clipboard.", true);
  });
}

// Local Storage History Management
function saveToHistory(analysis, text) {
  const item = {
    id: Date.now().toString(),
    timestamp: new Date().toISOString(),
    textPreview: text.length > 80 ? text.substring(0, 80) + "..." : text,
    fullText: text,
    riskLevel: analysis.riskLevel,
    riskScore: analysis.riskScore,
    category: analysis.category,
    analysisData: analysis
  };

  state.history.unshift(item);
  if (state.history.length > 20) {
    state.history = state.history.slice(0, 20);
  }

  localStorage.setItem("scamshield_history", JSON.stringify(state.history));
  updateHistoryUI();
}

function loadHistoryFromStorage() {
  try {
    const raw = localStorage.getItem("scamshield_history");
    if (raw) {
      state.history = JSON.parse(raw);
    }
  } catch (e) {
    state.history = [];
  }
  updateHistoryUI();
}

function updateHistoryUI() {
  elements.historyCounterBadge.textContent = state.history.length;
  const container = elements.historyListContainer;
  container.innerHTML = "";

  if (state.history.length === 0) {
    container.innerHTML = `
      <div class="text-center py-12 text-slate-500 text-xs">
        <i data-lucide="clock" class="w-8 h-8 mx-auto mb-2 text-slate-600"></i>
        <span>No recent scans yet. Analyze a message to populate history.</span>
      </div>
    `;
    initIcons();
    return;
  }

  state.history.forEach(item => {
    const timeAgo = formatTimeAgo(new Date(item.timestamp));
    const card = document.createElement("div");
    card.className = "p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-sky-500/50 cursor-pointer transition space-y-1.5";
    
    card.innerHTML = `
      <div class="flex items-center justify-between">
        <span class="px-2 py-0.5 rounded text-[10px] font-extrabold uppercase ${getRiskBadgeClass(item.riskLevel)}">
          ${item.riskLevel} (${item.riskScore})
        </span>
        <span class="text-[11px] text-slate-500">${timeAgo}</span>
      </div>
      <p class="text-xs text-slate-200 line-clamp-2 leading-relaxed">"${escapeHtml(item.textPreview)}"</p>
      <div class="flex items-center justify-between text-[11px] text-slate-400 pt-0.5">
        <span class="text-sky-400 font-medium">${escapeHtml(item.category)}</span>
        <span class="text-slate-500 text-[10px] flex items-center space-x-1">
          <span>Click to view</span>
          <i data-lucide="chevron-right" class="w-3 h-3"></i>
        </span>
      </div>
    `;

    card.addEventListener("click", () => {
      elements.inputText.value = item.fullText;
      updateTextCounts();
      state.currentAnalysis = item.analysisData;
      renderResults(item.analysisData, item.fullText);
      closeHistoryDrawer();
      showToast(`Loaded scan from ${timeAgo}`);
    });

    container.appendChild(card);
  });

  initIcons();
}

function clearHistory() {
  if (confirm("Are you sure you want to clear your local analysis history?")) {
    state.history = [];
    localStorage.removeItem("scamshield_history");
    updateHistoryUI();
    showToast("Analysis history cleared.");
  }
}

function openHistoryDrawer() {
  elements.historyBackdrop.classList.remove("hidden");
  elements.historyDrawer.classList.remove("translate-x-full");
}

function closeHistoryDrawer() {
  elements.historyDrawer.classList.add("translate-x-full");
  elements.historyBackdrop.classList.add("hidden");
}

// Settings Modal Management
function openSettingsModal() {
  elements.inputApiKey.value = state.apiKey;
  elements.settingsModal.classList.remove("hidden");
}

function closeSettingsModal() {
  elements.settingsModal.classList.add("hidden");
}

function saveSettings() {
  const key = elements.inputApiKey.value.trim();
  state.apiKey = key;
  if (key) {
    localStorage.setItem("scamshield_api_key", key);
    showToast("Gemini API key saved in browser session!");
    if (elements.navEngineText) {
      elements.navEngineText.textContent = "Gemini 2.5 Flash Connected";
    }
  } else {
    localStorage.removeItem("scamshield_api_key");
    showToast("Using Local Heuristic Defense Engine");
    loadServerStatus();
  }
  closeSettingsModal();
}

// Utilities
function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function formatTimeAgo(date) {
  const seconds = Math.floor((new Date() - date) / 1000);
  if (seconds < 60) return "Just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
