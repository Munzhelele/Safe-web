/**
 * Safe-web Browser Extension - content.js
 *   JavaScriptBehaviourMonitor
 *   IframeInspector            
 *   PopupDetector               
 *   ConsentPromptManager (UI)   
 */

(() => { 
  // Prevent double-injection if the content script is somehow loaded twice on the same page.
  if (window.__safeWebInjected) return;
  window.__safeWebInjected = true;

  const siteUrl = location.href;
  
  const OBVIOUS_CDNS = ["googletagmanager.com", "google-analytics.com", "gstatic.com"];
 /**
  * 
  * @param {*} url 
  * @returns 
  */
  function sameOrigin(url) {
    try { 
    
      return new URL(url, location.href).hostname === location.hostname;
    } catch {
      return true;
    }
  }

  function reportThreat(threatType, riskScore, affectedURL, affectedElement) {
    chrome.runtime
      .sendMessage({
        type: "THREAT_EVENT",
        threatType,
        riskScore,
        affectedURL: affectedURL || siteUrl,
        affectedElement: affectedElement || null,
        siteUrl,
      })
      .catch(() => {
        /*  ignore a dropped event */
      });
  }

  // ============================================================
  // JavaScriptBehaviourMonitor
  // ============================================================
  const JavaScriptBehaviourMonitor = {
    observedEvents: [],
    externalThreshold: 1,

    startMonitoring() {
      document.addEventListener("click", (e) => this.evaluateInteraction(e), true);
      this.observeMutations();
    },

    evaluateInteraction(e) {
      const el = e.target.closest?.("a[href], [onclick]");
      if (!el) return;
      const href = el.getAttribute("href") || "";
      if (!href || href.startsWith("#") || href.startsWith("javascript:")) return;

      let target;
      try {
        target = new URL(href, location.href);
      } catch {
        return;
      }

      if (target.hostname !== location.hostname) {
        // Same-origin navigations are normal (Alt Flow A of UC-01); only
        // flag genuinely external redirects triggered by an interaction.
        if (OBVIOUS_CDNS.some((d) => target.hostname.endsWith(d))) return;
        this.observedEvents.push({ href, ts: Date.now() });
        reportThreat("MALICIOUS_JS_REDIRECT", 55, target.href, describeElement(el));
      }
    },
/**
 * Observes DOM mutations to detect and evaluate inline scripts.
 */
    observeMutations() { 
      // Observe the DOM for added nodes and evaluate any inline scripts for sensitive API access.
      const mo = new MutationObserver((mutations) => {
        for (const m of mutations) {
          for (const node of m.addedNodes) {
            if (node.nodeType !== 1) continue;
            this.evaluateScript(node);
          }
        }
      }); 
      // Start observing the document for childList and subtree mutations to catch dynamically added scripts.
      mo.observe(document.documentElement, { childList: true, subtree: true });
    },

    /** Flags inline scripts that read sensitive browser APIs on injection. */
    evaluateScript(node) {
      if (node.tagName !== "SCRIPT") return;
      const text = node.textContent || "";
      const sensitive = /navigator\.geolocation|document\.cookie\s*=|eval\(|window\.open\(/i;
      if (sensitive.test(text)) {
        reportThreat("MALICIOUS_JS_REDIRECT", 65, siteUrl, "inline <script> with sensitive API access");
      }
    },
  };

  /**
   * Scans the page for iframes and classifies them based on their visibility, z-index, and cross-origin status. Suspicious iframes are reported and potentially removed from the DOM.
   */
  const IframeInspector = { 
    // Scans the page for iframes and classifies them based on their visibility, z-index, and cross-origin status. Suspicious iframes are reported and potentially removed from the DOM.
    scanPage() {
      document.querySelectorAll("iframe").forEach((el) => this.classifyIframeElement(el));
    },
   /**
    * Classifies an iframe element based on its visibility, z-index, and cross-origin status. Suspicious iframes are reported and potentially removed from the DOM.
    * @param {HTMLElement} el - The iframe element to classify.
    */
    async classifyIframeElement(el) {
      try { 
        // Skip if already checked to avoid duplicate processing.
        if (el.dataset?.safewebChecked) return;
        el.dataset.safewebChecked = "1"; 
        // Get the computed style of the iframe element to determine its visibility and z-index.
        const style = getComputedStyle(el);
        const hidden =
          style.display === "none" ||
          style.visibility === "hidden" ||
          parseInt(style.width, 10) <= 1 ||
          parseInt(style.height, 10) <= 1; 
        const highZIndex = parseInt(style.zIndex, 10) > 999;
        const src = el.getAttribute("src") || "";
        const crossOrigin = src && !sameOrigin(src);

        if (!src) return; 
        // If the iframe is cross-origin and either hidden or has a high z-index, it is considered suspicious. The code checks if the iframe's source is from a trusted domain and retrieves the mode for the site. If the iframe is not trusted and the mode is not "ALLOW_ALL", it is reported as a threat and removed from the DOM.
        if (crossOrigin && (hidden || highZIndex)) {
          let trusted = false;
          let mode = "FILTER_ONLY"; 
          // Attempt to check if the iframe's source is from a trusted domain and retrieve the mode for the site. If the background script is unreachable, treat it as untrusted with the default mode.
          try {
            const host = new URL(src).hostname;
            const [trustRes, modeRes] = await Promise.all([
              chrome.runtime.sendMessage({ type: "IS_TRUSTED_DOMAIN", domain: host }),
              chrome.runtime.sendMessage({ type: "GET_MODE_FOR_SITE", url: siteUrl }),
            ]);
            trusted = trustRes?.trusted;
            mode = modeRes?.mode || "FILTER_ONLY";
          } catch {
            /* background unreachable-fail closed (treat as untrusted, default mode) */
          }
          // Report the suspicious iframe as a threat with a risk score of 75, including the source URL and a description of the element.
          reportThreat("SUSPICIOUS_IFRAME", 75, src, describeElement(el));

          if (!trusted && mode !== "ALLOW_ALL") {
            el.setAttribute("data-safeweb-blocked", "true");
            el.remove();
          }
        }
      } catch {
        // logged as unverifiable, not blocked.
      }
    },
 // Sets up a MutationObserver to monitor the document for added nodes and classify any newly added iframes.
    observe() {
      this.scanPage();
      const mo = new MutationObserver((mutations) => {
        for (const m of mutations) {
          for (const node of m.addedNodes) {
            if (node.nodeType !== 1) continue;
            if (node.tagName === "IFRAME") this.classifyIframeElement(node);
            node.querySelectorAll?.("iframe").forEach((f) => this.classifyIframeElement(f));
          }
        }
      });
      mo.observe(document.documentElement, { childList: true, subtree: true });
    },
  };

  /**
   * Detects and evaluates popups and modal overlays on the page for scam patterns. Suspicious popups are reported and suppressed.
   */
  const PopupDetector = { 
  
    SCAM_PATTERNS: [ 
      // Common scam patterns to detect fake alerts and popups
      /virus/i,
      /device (has been|is) infected/i,
      /call .*(support|now)/i,
      /1-?\d{3}-?\d{3}-?\d{4}/,
      /0800[-\s]?\w+/i,
      /your (computer|device|iphone) is (locked|infected)/i,
      /security (warning|alert)/i,
      /claim your (prize|reward)/i,
    ],

    // Class/id naming ad networks commonly use for interstitial / lightbox
    // ad formats — reused alongside AdDetector's known-host list so a
    // full-page ad overlay can be recognised even without scam wording.
    AD_OVERLAY_HINT: /interstitial|popup-ad|ad-overlay|adsbygoogle|ad-slot|advert|dfp-ad|div-gpt-ad/i,

    /**
     * Scans the page for potential popups and modal overlays, evaluating them against known scam patterns. Suspicious elements are reported and suppressed.
     */
    scan() {
      const candidates = document.querySelectorAll(
        'div, section, [class*="modal"], [class*="popup"], [class*="overlay"], [class*="alert"]'
      );
      candidates.forEach((el) => this.evaluate(el));
    },
  /**
   * Evaluates a given element for potential scam patterns, checking its visibility, z-index, and inner text. If a match is found, the element is suppressed and reported as a threat.
   * Also catches disruptive ad interstitials that never call window.open() and
   * don't use scareware wording, so page-hook.js's popup-window hook and the
   * scam-text check above both miss them — these are recognised by behaviour
   * (covers most of the viewport) plus a correlation with ad content instead.
   * @param {HTMLElement} el - The element to evaluate for potential scam patterns.
   */
    evaluate(el) {
      if (el.dataset.safewebChecked) return;
      const style = getComputedStyle(el);
      const looksLikeOverlay =
        (style.position === "fixed" || style.position === "absolute") &&
        parseInt(style.zIndex, 10) > 1000;
      if (!looksLikeOverlay) return;

      const text = (el.innerText || "").slice(0, 500);
      const hit = this.SCAM_PATTERNS.some((re) => re.test(text));
      const isAdInterstitial = !hit && this.looksLikeAdInterstitial(el);
      el.dataset.safewebChecked = "1";

      if (hit) {
        this.suppressFakeAlert(el);
        reportThreat("FAKE_POPUP_ALERT", 95, siteUrl, describeElement(el));
      } else if (isAdInterstitial) {
        this.handleAdInterstitial(el);
      }
    },

    /**
     * True only when an overlay both (a) covers most of the viewport — the
     * behaviour that actually disrupts the page, same as a real pop-up would
     * — and (b) correlates with known ad content, either a known ad-network
     * iframe inside it or ad-style class/id naming. Requiring both avoids
     * flagging ordinary large modals (cookie notices, newsletter signups,
     * login prompts) that happen to be full-screen but aren't advertising.
     */
    looksLikeAdInterstitial(el) {
      const rect = el.getBoundingClientRect();
      const coverage = (rect.width * rect.height) / (window.innerWidth * window.innerHeight);
      if (coverage < 0.5) return false;

      if (this.AD_OVERLAY_HINT.test(el.className || el.id || "")) return true;

      return [...el.querySelectorAll("iframe[src]")].some((f) => {
        try {
          return AdDetector.isAdHost(new URL(f.getAttribute("src"), location.href).hostname);
        } catch {
          return false;
        }
      });
    },

    /** Reports and, outside ALLOW_ALL, suppresses a full-page ad interstitial. */
    async handleAdInterstitial(el) {
      reportThreat("AD_POPUP_OVERLAY", 60, siteUrl, describeElement(el));

      let mode = "FILTER_ONLY";
      try {
        const modeRes = await chrome.runtime.sendMessage({ type: "GET_MODE_FOR_SITE", url: siteUrl });
        mode = modeRes?.mode || "FILTER_ONLY";
      } catch {
        /* background unreachable — default mode */
      }

      if (mode !== "ALLOW_ALL") this.suppressFakeAlert(el);
    },

    suppressFakeAlert(el) {
      el.style.setProperty("display", "none", "important");
      el.setAttribute("aria-hidden", "true");
    },

    observe() {
      this.scan();
      const mo = new MutationObserver(() => this.scan());
      mo.observe(document.documentElement, { childList: true, subtree: true });
      // Fake alerts sometimes arrive shortly after load via a timer.
      setTimeout(() => this.scan(), 1500);
      setTimeout(() => this.scan(), 4000);
    },
  };

  /**
   * Detects and classifies ad elements on the page, reporting known ad hosts and suspicious ad slots. Depending on the user's preference, ads may be filtered or blocked entirely.
   */
  const AD_ELEMENT_SELECTOR =
    'iframe[src], ins.adsbygoogle, [id*="google_ads"], [id*="ad-slot"], [class*="ad-slot"], ' +
    '[data-ad-slot], [class*="advert"], [id*="advert"], [class*="dfp-ad"], [id*="div-gpt-ad"]';

  const AdDetector = {
    adDomains: [],
  /**
   * Loads the list of known ad domains from the background script and stores them in the adDomains array. If the request fails, the adDomains array is set to an empty array.
   */
    async loadDomains() {
      try {
        const res = await chrome.runtime.sendMessage({ type: "GET_AD_DOMAINS" });
        this.adDomains = res?.domains || [];
      } catch {
        this.adDomains = [];
      }
    },

    isAdHost(hostname) {
      return this.adDomains.some((d) => hostname === d || hostname.endsWith("." + d));
    },

    scan() {
      document.querySelectorAll(AD_ELEMENT_SELECTOR).forEach((el) => this.classify(el));
    },
  /**
   * Classifies an ad element based on its source URL and known ad hosts. If the element is identified as an ad, it is reported and may be blocked depending on the user's preference.
   * @param {HTMLElement} el - The ad element to classify.
   */
    async classify(el) {
      if (!el || el.dataset?.safewebAdChecked) return;
      el.dataset.safewebAdChecked = "1";

      const src = el.tagName === "IFRAME" ? el.getAttribute("src") || "" : "";
      let hostname = "";
      if (src) {
        try {
          hostname = new URL(src, location.href).hostname;
        } catch {
          /* ignore */
        }
      }

      const isKnownAdHost = hostname && this.isAdHost(hostname);
      const looksLikeAdSlot =
        !isKnownAdHost && /adsbygoogle|ad-slot|advert|dfp-ad|div-gpt-ad/i.test(el.className || el.id || "");

      if (!isKnownAdHost && !looksLikeAdSlot) return;

      // Report exactly which URL/host the ad is being served from so the
      // popup's Detection Log can show it, not just "an ad was found".
      reportThreat("AD_DETECTED", isKnownAdHost ? 25 : 15, src || siteUrl, describeElement(el));

      let mode = "FILTER_ONLY";
      try {
        const modeRes = await chrome.runtime.sendMessage({ type: "GET_MODE_FOR_SITE", url: siteUrl });
        mode = modeRes?.mode || "FILTER_ONLY";
      } catch {
        /* background unreachable, default mode */
      }

      if (mode === "BLOCK_ALL") {
        el.setAttribute("data-safeweb-blocked-ad", "true");
        el.style.setProperty("display", "none", "important");
      }
    },

    observe() {
      this.loadDomains().then(() => this.scan());
      const mo = new MutationObserver((mutations) => {
        for (const m of mutations) {
          for (const node of m.addedNodes) {
            if (node.nodeType !== 1) continue;
            this.classify(node);
            node.querySelectorAll?.(AD_ELEMENT_SELECTOR).forEach((f) => this.classify(f));
          }
        }
      });
      mo.observe(document.documentElement, { childList: true, subtree: true });
    },
  };

  /**
   * Listens for popup attempts and reports them as threats, indicating whether they were blocked or allowed based on user interaction. The report includes the URL of the attempted popup and a label describing the outcome.
   */
  document.addEventListener("safeweb:popup-attempt", (e) => {
    const detail = e.detail || {};
    const label = detail.blocked
      ? "window.open blocked (no user click detected)"
      : "window.open allowed (user-initiated)"; 
      // Report the popup attempt as a threat, indicating whether it was blocked or allowed based on user interaction. The report includes the URL of the attempted popup and a label describing the outcome.
    reportThreat("POPUP_WINDOW_BLOCKED", detail.blocked ? 80 : 15, detail.url || siteUrl, label);
  });
 // Helper function to describe an element for reporting purposes, including its tag name, ID, and class name.
  function describeElement(el) {
    if (!el || !el.tagName) return null;
    const id = el.id ? `#${el.id}` : "";
    const cls = el.className && typeof el.className === "string" ? "." + el.className.split(" ")[0] : ""; 
    // Return a string representation of the element, including its tag name, ID, and class name.
    return `${el.tagName.toLowerCase()}${id}${cls}`;
  }

  /**
   * Manages the display of a consent prompt for first-time visitors, allowing users to choose their advertisement filtering preference. The user's choice is saved and applied automatically on future visits.
   */
  const ConsentPromptManager = {
    async checkFirstVisit() {
      const res = await chrome.runtime.sendMessage({ type: "CHECK_FIRST_VISIT", siteUrl });
      return res;
    },

    async displayPrompt() {
      if (document.getElementById("safeweb-consent-overlay")) return;

      const host = document.createElement("div");
      host.id = "safeweb-consent-overlay";
      host.innerHTML = `
        <div class="sw-backdrop">
          <div class="sw-card" role="dialog" aria-modal="true" aria-label="Safe-web advertisement filtering preference">
            <div class="sw-badge">First visit</div>
            <div class="sw-domain">${escapeHtml(location.hostname)}</div>
            <div class="sw-headline">This site displays advertisements</div>
            <p class="sw-sub">Safe-web can filter malicious ads while letting legitimate ones through or block all ads, or let everything run. Your choice is saved for this site.</p>

            <label class="sw-option sw-selected" data-mode="FILTER_ONLY">
              <input type="radio" name="sw-mode" value="FILTER_ONLY" checked />
              <div>
                <div class="sw-opt-title">Filter only</div>
                <div class="sw-opt-desc">Blocks malicious ads, lets legitimate ones through. Recommended.</div>
              </div>
            </label>
            <label class="sw-option" data-mode="BLOCK_ALL">
              <input type="radio" name="sw-mode" value="BLOCK_ALL" />
              <div>
                <div class="sw-opt-title">Block all</div>
                <div class="sw-opt-desc">Block every ad on this site</div>
              </div>
            </label>
            <label class="sw-option" data-mode="ALLOW_ALL">
              <input type="radio" name="sw-mode" value="ALLOW_ALL" />
              <div>
                <div class="sw-opt-title">Allow all</div>
                <div class="sw-opt-desc">Disable filtering on this site</div>
              </div>
            </label>

            <div class="sw-persist-note">Your preference is saved and applied automatically on future visits.</div>

            <div class="sw-actions">
              <button class="sw-btn sw-btn-ghost" id="sw-skip">Skip for now</button>
              <button class="sw-btn sw-btn-primary" id="sw-save">Save preference</button>
            </div>
          </div>
        </div>
      `;
      document.documentElement.appendChild(host);

      host.querySelectorAll(".sw-option").forEach((opt) => {
        opt.addEventListener("click", () => {
          host.querySelectorAll(".sw-option").forEach((o) => o.classList.remove("sw-selected"));
          opt.classList.add("sw-selected");
        });
      });

      host.querySelector("#sw-skip").addEventListener("click", () => host.remove());

      host.querySelector("#sw-save").addEventListener("click", async () => {
        const mode = host.querySelector('input[name="sw-mode"]:checked').value;
        await this.savePreference(location.href, mode);
        host.remove();
      });
    },

    async savePreference(url, mode) {
      return chrome.runtime.sendMessage({ type: "SAVE_PREFERENCE", url, mode });
    },
  };

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  /**
   * Initializes the extension's functionality on the current page.
   * This includes checking if the page is likely to contain advertisements and displaying the consent prompt if necessary.
   */
  async function boot() {
    // Only prompt / scan on pages that plausibly carry advertising —
    // heuristic: presence of iframes, script density, or common ad-tag markers.
    const looksAdSupported =
      document.querySelectorAll("iframe, ins.adsbygoogle, [id*='google_ads'], [class*='ad-'], [class*='advert']")
        .length > 0 || document.scripts.length > 5;

    if (looksAdSupported) {
      const { isFirstVisit } = await ConsentPromptManager.checkFirstVisit().catch(() => ({
        isFirstVisit: false,
      }));
      if (isFirstVisit) {
        ConsentPromptManager.displayPrompt();
      }
    }

    JavaScriptBehaviourMonitor.startMonitoring();
    IframeInspector.observe();
    PopupDetector.observe();
    AdDetector.observe();

    // Keep the mode attribute fresh now that the background worker has
    // definitely answered (early-mode.js sets a first guess at document_start).
    try {
      const modeRes = await chrome.runtime.sendMessage({ type: "GET_MODE_FOR_SITE", url: siteUrl });
      document.documentElement.setAttribute("data-safeweb-mode", modeRes?.mode || "FILTER_ONLY");
    } catch {
      /* leave whatever early-mode.js already set */
    }
  }
// if the document is still loading, wait for DOMContentLoaded before booting; otherwise, boot immediately.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  /**
   * Re-evaluates everything already on the page against a newly-selected
   * mode, so a preference change in the popup takes effect immediately
   * instead of only on the next page load. Elements that were already
   * marked "checked" under the old mode are reset so the detectors look
   * at them again; ad elements that were hidden get shown again if the
   * new mode no longer calls for blocking them. (A cross-origin iframe
   * that was previously removed from the DOM entirely can't be restored
   * without a reload — that one genuine exception is called out below.)
   */
  function reapplyMode(mode) {
    document.documentElement.setAttribute("data-safeweb-mode", mode || "FILTER_ONLY");

    // Un-hide ads that were blocked under the old mode but shouldn't be now.
    document.querySelectorAll('[data-safeweb-blocked-ad="true"]').forEach((el) => {
      if (mode !== "BLOCK_ALL") {
        el.style.removeProperty("display");
        el.removeAttribute("data-safeweb-blocked-ad");
      }
    });

    // Clear "already checked" flags so AdDetector re-classifies every ad
    // slot against the new mode (e.g. newly hides them under BLOCK_ALL).
    document.querySelectorAll("[data-safeweb-ad-checked]").forEach((el) => {
      delete el.dataset.safewebAdChecked;
    });
    AdDetector.scan();

    // Re-run the iframe/fake-alert scanners too, in case ALLOW_ALL/BLOCK_ALL
    // changes whether a previously-flagged frame should be removed.
    document.querySelectorAll("[data-safeweb-checked]").forEach((el) => {
      delete el.dataset.safewebChecked;
    });
    IframeInspector.scanPage();
    PopupDetector.scan();
  }

  // Messages from the popup: rescan on demand, or apply a mode change live.
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "TRIGGER_RESCAN") {
      IframeInspector.scanPage();
      PopupDetector.scan();
      sendResponse({ ok: true });
    } else if (message.type === "MODE_CHANGED") {
      reapplyMode(message.mode);
      sendResponse({ ok: true });
    }
  });
})();
