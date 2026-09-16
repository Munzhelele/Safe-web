/**
 * Safe-web Browser Extension - popup.js
 * Implements SessionLogViewer (UC-11) plus the Filtering (UC-09) and
 * Whitelist (UC-10) tab controllers. All state lives in the background
 * service worker; this file only renders it and forwards user actions.
 */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const send = (msg) => chrome.runtime.sendMessage(msg);

let activeTabUrl = null;
let activeHostname = null;

const THREAT_TYPE_LABEL = {
  MALICIOUS_JS_REDIRECT: "MALICIOUS JS REDIRECT",
  SUSPICIOUS_IFRAME: "SUSPICIOUS IFRAME",
  REDIRECT_CHAIN: "REDIRECT CHAIN",
  MALICIOUS_URL: "MALICIOUS URL",
  BLOCKLIST_MATCH: "BLOCKLIST MATCH",
  FAKE_POPUP_ALERT: "FAKE POPUP ALERT",
  AD_DETECTED: "AD DETECTED",
  POPUP_WINDOW_BLOCKED: "POP-UP WINDOW",
  AD_POPUP_OVERLAY: "AD POP-UP OVERLAY",
};

const STAT_MAP = {
  FAKE_POPUP_ALERT: "popups",
  POPUP_WINDOW_BLOCKED: "popups",
  AD_POPUP_OVERLAY: "popups",
  BLOCKLIST_MATCH: "adsFound",
  AD_DETECTED: "adsFound",
  MALICIOUS_URL: "tracking",
  MALICIOUS_JS_REDIRECT: "scripts",
  SUSPICIOUS_IFRAME: "iframes",
  REDIRECT_CHAIN: "redirects",
};

const AD_THREAT_TYPES = new Set(["BLOCKLIST_MATCH", "AD_DETECTED"]);

function shortHost(url) {
  if (!url) return null;
  try {
    return new URL(url).hostname;
  } catch {
    return null; // not a full URL, nothing to show
  }
}

function timeAgo(iso) {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

function formatClock(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
// Tabs
function initTabs() {
  $$(".sw-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".sw-tab").forEach((b) => b.classList.remove("sw-tab-active"));
      $$(".sw-panel").forEach((p) => p.classList.remove("sw-panel-active"));
      btn.classList.add("sw-tab-active");
      $(`#tab-${btn.dataset.tab}`).classList.add("sw-panel-active");
    });
  });
}
// Header
async function loadActiveTab() {
  const res = await send({ type: "GET_ACTIVE_TAB_INFO" });
  activeTabUrl = res.url;
  try {
    activeHostname = activeTabUrl ? new URL(activeTabUrl).hostname : "\u2014";
  } catch {
    activeHostname = activeTabUrl || "\u2014";
  }
  $("#site-url").textContent = activeHostname;
  $("#filter-domain").textContent = activeHostname;

  const unsafe = activeTabUrl && activeTabUrl.startsWith("http://");
  $("#url-dot").classList.toggle("sw-dot-unsafe", !!unsafe);
}
// SessionLogViewer
const SessionLogViewer = {
  async renderLogEntries() {
    const { entries } = await send({ type: "GET_LOG_ENTRIES" });
    const siteEntries = activeHostname
      ? entries.filter((e) => (e.affectedURL || "").includes(activeHostname) || true)
      : entries;

    $("#entry-count").textContent = `${entries.length} ${entries.length == 1 ? "entry" : "entries"}`;

    const list = $("#log-list");
    if (!entries.length) {
      list.innerHTML = `<div class="sw-empty">No detections yet. Browse normally \u2014 Safe-web is watching quietly.</div>`;
    } else {
      list.innerHTML = entries
        .map((e) => {
          const cls = e.actionTaken === "BLOCKED" ? "" : e.actionTaken == "ALLOWED" ? "sw-log-green" : "sw-log-amber";
          const label = THREAT_TYPE_LABEL[e.threatType] || e.threatType;
          const host = shortHost(e.affectedURL);
          return `
            <div class="sw-log-entry ${cls}">
              <div class="sw-log-top">
                <span class="sw-log-type">${label}</span>
                <span class="sw-log-time">${formatClock(e.timestamp)}</span>
              </div>
              <div class="sw-log-summary">${escapeHtml(e.plainLanguageSummary)}</div>
              ${host ? `<div class="sw-log-url">${escapeHtml(host)}</div>` : ""}
            </div>`;
        })
        .join("");
    }

    this.updateReportTab(entries);
  },

  updateReportTab(entries) {
    const counts = { popups: 0, tracking: 0, scripts: 0, iframes: 0, redirects: 0 };
    let adsFound = 0;
    let adsBlocked = 0;
    let maxRisk = 0;
    let blockedCount = 0;

    for (const e of entries) {
      if (AD_THREAT_TYPES.has(e.threatType)) {
        // "Found" = every ad the site actually served, blocked or not.
        adsFound++;
        if (e.actionTaken == "BLOCKED") adsBlocked++;
      } else {
        const key = STAT_MAP[e.threatType];
        if (key && e.actionTaken != "ALLOWED") counts[key]++;
      }
      maxRisk = Math.max(maxRisk, e.riskScore || 0);
      if (e.actionTaken == "BLOCKED") blockedCount++;
    }

    for (const key of Object.keys(counts)) {
      const card = document.querySelector(`.sw-stat-card[data-key="${key}"] .sw-stat-num`);
      if (card) card.textContent = counts[key];
    }
    const adsFoundCard = document.querySelector('.sw-stat-card[data-key="adsFound"] .sw-stat-num');
    if (adsFoundCard) adsFoundCard.textContent = adsFound;
    const adsBlockedCard = document.querySelector('.sw-stat-card[data-key="adsBlocked"] .sw-stat-num');
    if (adsBlockedCard) adsBlockedCard.textContent = adsBlocked;

    $("#risk-fill").style.width = `${maxRisk}%`;

    let level = "SAFE";
    let pillClass = "sw-pill-safe";
    if (maxRisk >= 90) {
      level = "CRITICAL";
      pillClass = "sw-pill-critical";
    } else if (maxRisk >= 70) {
      level = "HIGH";
      pillClass = "sw-pill-high";
    } else if (maxRisk >= 30) {
      level = "MEDIUM";
      pillClass = "sw-pill-medium";
    } else if (maxRisk > 0) {
      level = "LOW";
      pillClass = "sw-pill-low";
    }

    const pill = $("#risk-pill");
    pill.textContent = level;
    pill.className = `sw-pill ${pillClass}`;

    $("#leave-page").disabled = maxRisk < 70;

    if (entries[0]) {
      $("#scan-time").textContent = `Scanned ${timeAgo(entries[0].timestamp)}`;
    } else {
      $("#scan-time").textContent = "Scanned just now";
    }
  },

  async clearLog() {
    await send({ type: "CLEAR_LOG" });
    await this.renderLogEntries();
  },
};

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str || "";
  return div.innerHTML;
}

// Filtering tab
async function initFilteringTab() {
  const { mode } = await send({ type: "GET_MODE_FOR_SITE", url: activeTabUrl });
  $$('input[name="filter-mode"]').forEach((input) => {
    input.checked = input.value ==mode;
  });

  $("#save-site").addEventListener("click", async () => {
    const mode = $('input[name="filter-mode"]:checked').value;
    await send({ type: "SAVE_PREFERENCE", url: activeTabUrl, mode });
    await pushModeToActiveTab(mode);
    flashButton($("#save-site"), "Saved \u2713");
  });

  $("#apply-global").addEventListener("click", async () => {
    const mode = $('input[name="filter-mode"]:checked').value;
    await send({ type: "SAVE_PREFERENCE", url: "global-default", mode });
    flashButton($("#apply-global"), "Applied \u2713");
  });
}

// Tells the active tab's content script to apply a mode change immediately,
// instead of waiting for the next page load to pick up the new preference.
async function pushModeToActiveTab(mode) {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tabs[0]?.id) {
    chrome.tabs.sendMessage(tabs[0].id, { type: "MODE_CHANGED", mode }).catch(() => {
      // No content script in this tab (e.g. chrome:// page) — nothing to do.
    });
  }
}

function flashButton(btn, text) {
  const original = btn.textContent;
  btn.textContent = text;
  setTimeout(() => (btn.textContent = original), 1200);
}

// Whitelist tab
async function renderWhitelist() {
  const { list } = await send({ type: "LIST_WHITELIST" });
  const container = $("#whitelist-list");
  if (!list.length) {
    container.innerHTML = `<div class="sw-empty">No trusted networks added yet.</div>`;
    return;
  }
  container.innerHTML = list
    .map(
      (e) => `
      <div class="sw-whitelist-item" data-domain="${escapeHtml(e.domain)}">
        <div class="sw-whitelist-domain"><span class="sw-check">\u2713</span> ${escapeHtml(e.domain)}</div>
        <button class="sw-remove" data-domain="${escapeHtml(e.domain)}">\u2715</button>
      </div>`
    )
    .join("");

  $$(".sw-remove").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await send({ type: "REMOVE_WHITELIST", domain: btn.dataset.domain });
      renderWhitelist();
    });
  });
}

function initWhitelistTab() {
  $("#whitelist-add").addEventListener("click", async () => {
    const input = $("#whitelist-input");
    const domain = input.value.trim();
    if (!domain) return;
    await send({ type: "ADD_WHITELIST", domain });
    input.value = "";
    renderWhitelist();
  });

  $("#whitelist-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#whitelist-add").click();
  });

  renderWhitelist();
}

// Footer action
function initFooter() {
  $("#rescan").addEventListener("click", async () => {
    await send({ type: "RESCAN" });
    flashButton($("#rescan"), "Rescanning\u2026");
    setTimeout(() => SessionLogViewer.renderLogEntries(), 1200);
  });

  $("#leave-page").addEventListener("click", async () => {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]?.id) chrome.tabs.update(tabs[0].id, { url: "about:blank" });
  });

  $("#clear-log").addEventListener("click", () => SessionLogViewer.clearLog());
}
// Boot
(async function init() {
  initTabs();
  await loadActiveTab();
  await SessionLogViewer.renderLogEntries();
  await initFilteringTab();
  initWhitelistTab();
  initFooter();

  // Live-refresh while the popup is open.
  setInterval(() => SessionLogViewer.renderLogEntries(), 2500);
})();
