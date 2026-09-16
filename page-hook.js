/**
 * Safe-web Browser Extension page-hook.js
 * Runs in the page's MAIN world (see manifest.json: "world": "MAIN").
 *
 * Why this file exists: content.js runs in an ISOLATED world, which has
 * its own copy of `window`. If content.js does `window.open = ...`, it
 * only overrides *its own* isolated copy — it never sees or affects calls
 * the page's own <script> tags make to the page's real window.open. That
 * isolation is exactly why the previous version of this extension could
 * never actually block a pop-up: it could only detect scareware *text*
 * after the fact (PopupDetector), never stop a window.open() call itself.
 *
 * This file runs in the same JS context as the page, so overriding
 * window.open here actually works. It talks back to content.js via a
 * CustomEvent on `document`, since the DOM (unlike `window`) is shared
 * between the MAIN and ISOLATED worlds.
 *
 * Decision of whether to block is read synchronously from a DOM attribute
 * (data-safeweb-mode) set by early-mode.js / content.js, since DOM access
 * is synchronous and shared across worlds while messaging is not.
 */ 

(() => { 
  if (window._safeWebHookInstalled) return;
  window._safeWebHookInstalled = true;
  function getMode() {
    return document.documentElement.getAttribute("data-safeweb-mode") || "FILTER_ONLY";
  }
 
  function shouldBlock() {
    return getMode() !== "ALLOW_ALL";
  }
 
  function reportToContentScript(type, detail) {
    document.dispatchEvent(new CustomEvent("safeweb:" + type, { detail }));
  }
 
  // Known ad-manager / malicious script hostnames.
  // Matched as exact hostname or any subdomain thereof.
  const BLOCKED_SCRIPT_HOSTS = [
    "wpadmngr.com",
    "tuckerclassesjackal.com",
    "zap.buzz",
    "aclib.com",
    "aclibsa.com",
    "popads.net",
    "popcash.net",
    "clickadu.com",
    "adcash.com",
    "trafficfactory.biz",
    "onclickads.net",
    "propellerads.com",
    "adsterra.com",
    "exoclick.com",
    "juicyads.com",
    "plugrush.com",
    "hilltopads.net",
    "royalads.net",
    "tpnads.com",
  ];
 
  function isBlockedHost(urlString) {
    if (!urlString) return false;
    try {
      const host = new URL(urlString, location.href).hostname.toLowerCase();
      return BLOCKED_SCRIPT_HOSTS.some(
        (blocked) => host === blocked || host.endsWith("." + blocked)
      );
    } catch {
      return false;
    }
  }
 
  
  // Blocks auto-triggered pop-ups (no user gesture) in any mode except
  // ALLOW_ALL. The userActivation check catches timers, iframe-triggered
  // opens, and window.open calls fired on page load.
 
  const nativeOpen = window.open;
  window.open = function (url, target, features) {
    const mode = getMode();
    let userGesture = true;
    try {
      userGesture = !!(navigator.userActivation && navigator.userActivation.isActive);
    } catch {
      userGesture = true;
    }
 
    const blocked = !userGesture && mode !== "ALLOW_ALL";
 
    reportToContentScript("popup-attempt", {
      url: url || "",
      target: target || "",
      userGesture,
      blocked,
});
 
    if (blocked) return null;
    return nativeOpen.call(window, url, target, features);
}; 
function stubAclib() {
    const stub = {
      runPop: function (opts) {
        if (shouldBlock()) {
          reportToContentScript("popup-attempt", {
            url: "aclib:runPop:" + (opts && opts.zoneId ? opts.zoneId : ""),
            target: "",
            userGesture: false,
            blocked: true,
            vector: "aclib.runPop",
          });
          return;
        }
      },
      // Stub out other common ACLib entry points so partial SDK loads
      // do not throw and fall through to a native pop.
      runBanner: function () {},
      runInPage: function () {},
      run: function () {},
    };
    // Only install if not already stubbed (avoid overwriting a real ALLOW_ALL session).
    if (!window.aclib || !window.aclib._safewebStub) {
      window.aclib = stub;
      window.aclib._safewebStub = true;
    }
  }
 
  stubAclib();
  // Re-apply after any script that might overwrite it (MutationObserver
  // in the MAIN world watches for aclib re-definition via script load).
  const aclibPollId = setInterval(() => {
    if (window.aclib && !window.aclib._safewebStub && shouldBlock()) {
      stubAclib();
    }
  }, 80);
  // Stop polling once the page is fully loaded after that, no new SDK
  // scripts should be injecting aclib for the first time.
  window.addEventListener("load", () => clearInterval(aclibPollId), { once: true });
  // Obfuscated scripts on this page decode hidden 0×0 iframes and inject
  // them via document.write(). We intercept the write and strip <iframe>
  // and <script> tags pointing at blocked hosts before they reach the parser.
 
  const nativeWrite = document.write.bind(document);
  const nativeWriteln = document.writeln.bind(document);
  function sanitiseDocWrite(html) {
    if (!shouldBlock()) return html;
    // Use a sandboxed DOMParser so we can inspect the markup without
    // executing it.DOMParser does not run scripts or load resources.
    try {
      const doc = new DOMParser().parseFromString(html, "text/html");
      let blocked = false;
      doc.querySelectorAll("iframe[src], script[src]").forEach((el) => {
        const src = el.getAttribute("src") || "";
        if (isBlockedHost(src)) {
          el.remove();
          blocked = true;
          reportToContentScript("popup-attempt", {
            url: src,
            target: "",
            userGesture: false,
            blocked: true,
            vector: "document.write <" + el.tagName.toLowerCase() + ">",
          });
        }
      });
 
      if (!blocked) return html; // nothing to strip pass through unchanged
 
      // Reserialise only the <body> children (document.write targets body).
      return doc.body.innerHTML;
    } catch {
      // If DOMParser fails for any reason, pass through — don't break the page.
      return html;
    }
  }
 
  document.write = function (...args) {
    return nativeWrite(sanitiseDocWrite(args.join("")));
  };
  document.writeln = function (...args) {
    return nativeWriteln(sanitiseDocWrite(args.join("") + "\n"));
  };
 

  // The obfuscated loader on this page builds a <script> element, sets its
  // .src to an ad-manager host
  // and appends it to <head>. We wrap createElement so that any <script>
  // element whose src is later set to a blocked host never loads.
 
  const nativeCreateElement = document.createElement.bind(document);
  document.createElement = function (tag, options) {
    const el = nativeCreateElement(tag, options);
 
    if (tag.toLowerCase() !== "script") return el;
 
    // Intercept .src assignment on the created element.
    let _src = "";
    const descriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, "src");
 
    Object.defineProperty(el, "src", {
      get() {
        return _src;
      },
      set(value) {
        _src = value;
        if (shouldBlock() && isBlockedHost(value)) {
          // Neuter the element: set type to something the browser won't
          // execute, and blank the src so no request fires.
          el.type = "text/blocked-by-safeweb";
          // Do NOT call the native setter with the blocked URL.
          reportToContentScript("popup-attempt", {
            url: value,
            target: "",
            userGesture: false,
            blocked: true,
            vector: "createElement script",
          });
          return;
        }
        // Safe src-delegate to the prototype setter so the browser
        // handles it normally (including relative URL resolution).
        if (descriptor && descriptor.set) descriptor.set.call(el, value);
      },
      configurable: true,
    });
    return el;
  };
  // Belt-and-suspenders: if a script somehow got appended before our
  // createElement hook was in place, or was injected via innerHTML, abort it.
 
  const domWatcher = new MutationObserver((mutations) => {
    if (!shouldBlock()) return;
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        if (
          node.tagName === "SCRIPT" &&
          node.src &&
          isBlockedHost(node.src)
        ) {
          node.type = "text/blocked-by-safeweb";
          // Clearing src after append doesn't stop an already-started fetch
          // in all browsers, but setting type prevents execution even if
          // the bytes arrive.
          reportToContentScript("popup-attempt", {
            url: node.src,
            target: "",
            userGesture: false,
            blocked: true,
            vector: "DOM mutation script",
          });
        }
        // Also catch hidden 0×0 iframes injected via innerHTMLand appendChild.
        if (node.tagName === "IFRAME") {
          const src = node.getAttribute("src") || "";
          if (isBlockedHost(src)) {
            node.remove();
            reportToContentScript("popup-attempt", {
              url: src,
              target: "",
              userGesture: false,
              blocked: true,
              vector: "DOM mutation iframe",
            });
          }
        }
      }
    }
  });
  domWatcher.observe(document.documentElement, { childList: true, subtree: true });
})();
