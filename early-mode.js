/**
 * Safe-web Browser Extension — early-mode.js
 * Runs at document_start, isolated world (default). Sole job: ask the
 * background service worker for this site's filtering mode and stamp it
 * onto <html data-safeweb-mode="..."> as fast as possible, so page-hook.js
 * (MAIN world, also document_start) has a real value to read the instant
 * a script on the page calls window.open — rather than only finding out
 * once content.js finishes at document_idle, by which point an early
 * pop-up/pop-under has often already fired.
 */
(async () => {
  try {
    const res = await chrome.runtime.sendMessage({ type: "GET_MODE_FOR_SITE", url: location.href });
    document.documentElement.setAttribute("data-safeweb-mode", res?.mode || "FILTER_ONLY");
  } catch {
    document.documentElement.setAttribute("data-safeweb-mode", "FILTER_ONLY");
  }
})();
