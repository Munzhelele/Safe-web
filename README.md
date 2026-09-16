# Safe-web Browser Extension

A functional Manifest V3 Chrome/Edge/Brave extension implementing the design : selective, user-controlled malvertising filtering with real-time
detection, a session threat log, and a per-site consent model.

## Install (load unpacked)

1. Open `chrome://extensions` (or `edge://extensions`, `brave://extensions`).
2. Turn on **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select this folder (`safe-web-extension/`).
4. Pin the Safe-web icon to the toolbar for easy access.
5. Visit any ad-supported site (a news site works well); the first-visit consent
   prompt should appear within a second or two.

## What's actually implemented

| Subsystem | File | Classes & behaviour |
| Detection Engine | `content.js` | `JavaScriptBehaviourMonitor`, `IframeInspector`, `PopupDetector` — live `MutationObserver`-based detection in-page |
| Detection Engine | `background.js` | `URLClassifier`, `RedirectChainAnalyser`, `BlocklistMatcher` (Trie) — network-level analysis via `webRequest` |
| User Control | `background.js` + `content.js` | `ConsentPromptManager`, `FilteringModeEngine`, `WhitelistManager`, `SitePreferenceStore` |
| Session Management | `background.js` | `SessionThreatLog`, `BadgeNotificationService`, `BrowsingSession`, dynamic `declarativeNetRequest` blocking |
| Popup UI | `popup.html/js/css` | Report, Detection Log, Filtering, and Whitelist tabs (`SessionLogViewer`) |

Detected threats are:
- **Blocked** at the network level via `declarativeNetRequest` dynamic rules (for confirmed blocklist matches) and removed from the DOM (for flagged hidden/cross-origin iframes and fake alert overlays) — unless the domain is on your whitelist or the site is set to `ALLOW_ALL`.
- **Logged** to the session threat log in plain language (FR-10), with the toolbar badge updated (FR-09).

All data — preferences, whitelist, and the threat log — stays in `chrome.storage.local` (NFR-01/NFR-08); nothing is sent off-device except the periodic blocklist refresh, which is currently disabled by default (see below).

## Known limitations (honest scope notes in the spirit of D04)

- **`BLOCK_ALL` mode now actually blocks ads**, not just malicious behaviour. `AdNetworkRegistry` in `background.js` holds a small list of known ad-serving domains (Google/DoubleClick, Criteo, Taboola, Outbrain, etc.) and registers `declarativeNetRequest` rules scoped to the specific site via `initiatorDomains` whenever you save `BLOCK_ALL` for that site — so it blocks ads there without affecting other sites still on `FILTER_ONLY`. Previously `BLOCK_ALL` only re-labelled events the malicious-behaviour detectors *already* flagged, which meant it never blocked ordinary/legitimate ads (a real gap against the UI's own promise now fixed).
- **YouTube specifically will still show some ads even in `BLOCK_ALL` mode.** Many YouTube video ads are server-side-inserted (SSAI) — stitched directly into the same `googlevideo.com` stream as the actual video — so there's no separate "ad request" to a blockable domain at all. This is a known hard limitation that even dedicated tools like uBlock Origin have to work around with YouTube-specific player scripts, not plain domain blocking; Safe-web's `AdNetworkRegistry` will stop the *surrounding* ad requests (companion banners, pre-roll served from `doubleclick.net`, etc.) but not SSAI-stitched in-stream ads.
- **"Apply globally" in the Filtering tab currently only stores a placeholder preference** — it isn't yet read as a fallback default when a new site has no saved preference (`getModeForSite()` always falls back to `FILTER_ONLY` today). Wiring a real global default would mean checking a `settings:global` fallback in `FilteringModeEngine.getModeForSite()` before defaulting to `FILTER_ONLY`.
- **Blocklist now pulls live from uBlock Origin's `badware.txt`** (`fetchRemoteBlocklist()` in `background.js`), parsed from Adblock Plus filter syntax down to plain domains via `parseAdblockList()`. It loads the small built-in seed list instantly on startup/install so protection is live immediately, then upgrades to the real feed in the background once the fetch completes, and refreshes daily via `chrome.alarms`. If the fetch fails (offline, list moved, etc.) it silently keeps whatever's already loaded rather than wiping the blocklist. Swap `UBO_BADWARE_LIST_URL` for your own compiled artifact (e.g. the Bloom-filter approach from the Deliverable 06 deployment-diagram discussion) if you want a larger list instead.
- **URL risk scoring** (`URLClassifier`) only runs on explicitly-reported `MALICIOUS_URL` events and is not yet wired into every link on a page — extending it to score every outbound link would need a performance pass (NFR-02/NFR-04) beyond this prototype's scope.
- **Fake-popup detection** uses a pattern-matching heuristic (`PopupDetector.SCAM_PATTERNS`) rather than the structural/text-density analysis described in FR-07; it will miss cleverly-worded scam overlays.
- **`hashId()`** is a fast string hash used as a storage-key id, not real SHA-256 — fine for local key uniqueness, but replace with `crypto.subtle.digest` if you need cryptographic guarantees.
- Icons are simple generated placeholders (`icons/`) ; swap in real branded artwork before shipping.

## Data source & licensing

The live blocklist is parsed from uBlock Origin's `uAssets` repository (`filters/badware.txt`), which is GPL-3.0 licensed. If you swap in EasyList or another list, check its license too — EasyList is CC-BY-SA 3.0 with an additional restriction that commercial use requires permission from the EasyList authors.

## Testing it locally

Trigger detections manually from the DevTools console on any page (after loading the extension):
Then open the popup; the Report tab's stat cards and risk meter, and the Detection Log tab, should update within a couple of seconds.
