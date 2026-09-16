/**
 * Safe-web Browser Extension
 *
 * Implements, per Deliverable 04/05/06 class diagrams:
 *   Session Management Subsystem: Trie, MaliciousBlocklist/BlocklistMatcher,
 *     SessionThreatLog, ThreatLogEntry, BadgeNotificationService, BrowsingSession
 *   Detection Engine (network-facing parts): URLClassifier, RedirectChainAnalyser,
 *     BlocklistMatcher, DetectionEngine (orchestrator)
 *   User Control Layer (persistence + policy): SitePreferenceStore, FilteringModeEngine,
 *     WhitelistManager
 *
 * chrome.storage.local key schema
 *   pref:{siteId}      -> SitePreference
 *   wl:{whitelistId}   -> WhitelistEntry
 *   session:current    -> BrowsingSession
 *   log:{sessionId}    -> ThreatLogEntry[]
 *   bl:{blocklistId}   -> BlocklistEntry   
 *   settings:global    -> { filterMode, version, onboarded }
 */

// ============================================================
// Utilities
// ============================================================

/** Cheap deterministic string hash used as a storage-key id */
function hashId(str) { 
  // hashing algorithm that produces a 32-bit integer, then converts to base36 for compactness
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0; // force to 32-bit integer
  }
  return "h" + Math.abs(h).toString(36); 
}
/**
 * Normalizes a domain string by extracting its hostname and removing the 'www.' prefix.
 * @param {*} input 
 * @returns 
 */
function normaliseDomain(input) {
  try { 
    // accepts either a full URL or a bare domain string
    // If the input is a full URL, create a URL object to extract the hostname
    const u = input.includes("://") ? new URL(input) : new URL("https://" + input); 
  // If the input is a bare domain string, prepend "https://" to create a valid URL
    return u.hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return String(input).replace(/^www\./, "").toLowerCase();
  }
}
/**
 *  Returns the current timestamp in ISO 8601 format.
 */
function nowISO() {
  return new Date().toISOString();
}
/**
 * Generates a random UUID (version 4) string.
 * @returns {string} A randomly generated UUID.
 */
function uuidv4() { 
  
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Parses an Adblock-style filter list and extracts unique domain names.
 * @param {string} text - The raw text of the Adblock filter list.
 * @returns {string[]} An array of unique domain names extracted from the list.
 */
function parseAdblockList(text) { 
  // Use a Set to avoid duplicates
  const domains = new Set(); 
// Iterate over each line in the text, trimming whitespace and skipping comments, headers, exceptions, and cosmetic filters
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!") || line.startsWith("[")) continue; // comment/header
    if (line.startsWith("@@")) continue;
    if (line.includes("##") || line.includes("#@#") || line.includes("#?#")) continue; // cosmetic filter
    // Match the line against the pattern for network domain-blocking rules
    const match = line.match(/^\|\|([a-z0-9.-]+)\^/i);
    if (match) domains.add(match[1].toLowerCase());
  } 
  // Return an array of unique domains
  return [...domains];
}

// URL of the uBlock Origin badware filter list, used as the default remote blocklist source.
const UBO_BADWARE_LIST_URL =
  "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt";

async function fetchRemoteBlocklist(url = UBO_BADWARE_LIST_URL) {
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const domains = parseAdblockList(text);
    if (!domains.length) throw new Error("parsed 0 domains — unexpected list format");
    return domains;
  } catch (e) {
    console.warn("Safe-web: remote blocklist fetch/parse failed:", e);
    return null;
  }
}

/**
 * A node in the Trie data structure, representing a single character and its children.
 * Each node can also mark the end of a valid domain.
 */
class TrieNode {
  constructor() {
    this.children = new Map();
    this.isEnd = false;
  }
}

/**
 * A Trie data structure for efficient domain name lookups.
 */
class Trie {
  constructor() {
    this.root = new TrieNode();
    this.size = 0;
  }

  /** Domains are inserted reversed-label-order so subdomain matches share prefixes. */
  static keyOf(domain) {
    return domain.split(".").reverse().join(".");
  }

  insert(domain) {
    const key = Trie.keyOf(domain);
    let node = this.root;
    for (const ch of key) {
      if (!node.children.has(ch)) node.children.set(ch, new TrieNode());
      node = node.children.get(ch);
    }
    if (!node.isEnd) this.size++;
    node.isEnd = true;
  }
  /**
   * Searches for a domain in the Trie.
   * @param {string} domain - The domain to search for.
   * @returns {boolean} True if the domain is found, false otherwise.
   */
  search(domain) {
    const key = Trie.keyOf(domain);
    let node = this.root;
    for (const ch of key) {
      if (!node.children.has(ch)) return false;
      node = node.children.get(ch);
    }
    return node.isEnd;
  }

  /**
   * Deletes a domain from the Trie.
   * @param {string} domain - The domain to delete.
   * @returns {boolean} True if the domain was found and deleted, false otherwise.
   */
  delete(domain) {
    const key = Trie.keyOf(domain);
    let node = this.root;
    for (const ch of key) {
      if (!node.children.has(ch)) return false;
      node = node.children.get(ch);
    }
    if (node.isEnd) {
      node.isEnd = false;
      this.size--;
      return true;
    }
    return false;
  }
}

/**
 * BlocklistMatcher manages a Trie of known malicious domains and provides methods to load, update, and query the blocklist.
 */
class BlocklistMatcher { 
  /**
   * constructor initializes the BlocklistMatcher with an empty Trie and a null lastUpdated timestamp.
   */
  constructor() {
    this.blocklist = new Trie();
    this.lastUpdated = null;
  }

  /**
   * Returns a predefined list of seed domains known to be malicious. These domains are used to initialize the blocklist when no remote data is available.
   */
  static get SEED_DOMAINS() {
    return [
      "malvert-cdn.xyz",
      "click.cc",
      "payload.ru",
      "ad-fraud-network.top",
      "scam-alert-popup.info",
      "fake-antivirus-warning.site",
      "redir-tracker.click",
      "malicious-ads.biz",
      // Pop-under / malicious ad networks confirmed on sites like yourbittorrent.com
      "zap.buzz",
      "wpadmngr.com",
      "tuckerclassesjackal.com",
      "aclib.com",
      "aclibsa.com",
      "popcash.net",
      "clickadu.com",
      "trafficfactory.biz",
      "onclickads.net",
      "adsterra.com",
      "exoclick.com",
      "juicyads.com",
      "plugrush.com",
      "hilltopads.net",
    ];
  }
 /**
  * Loads the blocklist with the provided data.
  * @param {Array<string}} data - The list of domains to load into the blocklist.
  */
  async loadBlocklist(data) { 
    // If no data is provided, use the predefined seed domains.
    const domains = Array.isArray(data) ? data : BlocklistMatcher.SEED_DOMAINS;
    this.blocklist = new Trie(); 
    // Insert each domain into the Trie for efficient lookups.
    for (const domain of domains) this.blocklist.insert(domain);
    this.lastUpdated = new Date();

    // Persist the blocklist entries in chrome.storage.local for future reference and synchronization with declarativeNetRequest rules.
    const entries = {}; 
    // Generate a unique blocklistId for each domain and create an entry object with metadata.
    for (const domain of domains) { 
      // Generate a unique blocklistId by hashing the domain.
      const id = hashId(domain);
      entries[`bl:${id}`] = {
        blocklistId: id,
        domain,
        source: "seed+community",
        addedAt: nowISO(),
        hitCount: 0,
      };
    } 
    // Store the entries in chrome.storage.local and synchronize the dynamic rules for declarativeNetRequest to enforce blocking at the network level.
    await chrome.storage.local.set(entries);
    await this._syncDynamicRules(domains);
  }
/**
 * Updates the blocklist with new entries and synchronizes the dynamic rules for declarativeNetRequest.
 * @param {Array<string>} newEntries - The list of new domains to add to the blocklist.
 * */
  async update(newEntries) { 
    // Insert each new domain into the Trie for efficient lookups.
    for (const domain of newEntries) this.blocklist.insert(domain);
    this.lastUpdated = new Date();
    await this._syncDynamicRules(newEntries, { additive: true });
  }

  /**
   * Synchronizes the dynamic rules for declarativeNetRequest based on the current blocklist.
   * @param {Array<string>} domains - The list of domains to synchronize with declarativeNetRequest.
   * @param {Object} options - Optional parameters for synchronization.
   * @param {boolean} options.additive - If true, adds new rules without removing existing ones; otherwise, replaces all existing rules.
   */
  async _syncDynamicRules(domains, options) {
    const additive = options && options.additive; 
    // If additive is true, we will add new rules without removing existing ones; otherwise, we will replace all existing rules.
    try { 
      // Retrieve the existing dynamic rules from declarativeNetRequest.
      const existing = await chrome.declarativeNetRequest.getDynamicRules();
      const removeRuleIds = additive ? [] : existing.map((r) => r.id);
      let nextId = additive
        ? Math.max(1000, ...existing.map((r) => r.id)) + 1
        : 1000;
// Create new rules for the provided domains, limiting to the first 4000 to avoid exceeding the maximum allowed by declarativeNetRequest.
      const addRules = domains.slice(0, 4000).map((domain) => ({
        id: nextId++,
        priority: 1,
        action: { type: "block" },
        condition: {
          requestDomains: [domain],
          resourceTypes: ["script", "sub_frame", "image", "xmlhttprequest", "media"],
        },
      }));
   // Update the dynamic rules in declarativeNetRequest by removing old rules and adding new ones.
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
    } catch (e) { 
      // Log a warning if there was an error synchronizing the declarativeNetRequest rules, but do not throw an exception to avoid breaking the extension's functionality.
      console.warn("Safe-web: could not sync declarativeNetRequest rules", e);
    }
  }
   /**
    * Looks up a domain in the blocklist Trie.
    * @param {string} domain - The domain to look up.
    * @returns {boolean} - True if the domain is in the blocklist, false otherwise.
    */
  lookup(domain) {
    return this.blocklist.search(normaliseDomain(domain));
  }

  getEntryCount() {
    return this.blocklist.size;
  }
}

/**
 * URLClassifier analyzes URLs to extract features and calculate a risk score based on heuristics.
 */
class URLClassifier { 
  /**
   * constructor initializes the URLClassifier with predefined weightings for different features.
   */
  constructor() {
    this.weightings = {
      ipHostname: 30,
      noHttps: 20,
      deepPath: 15,
      numericPatterns: 15,
      manySubdomains: 20,
    };
  }
   /**
    * Extracts features from a given URL string, including length, subdomain count, path depth, numeric patterns, HTTPS usage, and whether the hostname is an IP address.
    * @param {string} urlString - The URL string to analyze.
    * @returns {Object|null} - An object containing the extracted features or null if the URL is invalid.
    */
  extractFeatures(urlString) { 
    // Attempt to create a URL object from the provided string. If it fails, return null to indicate an invalid URL.
    let u;
    try {
      u = new URL(urlString);
    } catch {
      return null;
    }
    const hostnameIsIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(u.hostname);
    const subdomains = Math.max(0, u.hostname.split(".").length - 2);
    const pathDepth = u.pathname.split("/").filter(Boolean).length;
    const numericPatterns = /\d{3,}/.test(u.pathname) || /\d{3,}/.test(u.hostname);
    const httpsUsage = u.protocol === "https:";
    return {
      length: urlString.length,
      subdomains,
      pathDepth,
      numericPatterns,
      httpUsage: !httpsUsage,
      hostnameIsIp,
    };
  }
  /**
   * Calculates a risk score based on the extracted features and predefined weightings.
   * @param {Object} features - The extracted features from a URL.
   * @returns {number} - The calculated risk score, capped at 100.
   */
  calculateRiskScore(features) {
    if (!features) return 0;
    let score = 0;
    if (features.hostnameIsIp) score += this.weightings.ipHostname;
    if (features.httpUsage) score += this.weightings.noHttps;
    if (features.pathDepth >= 3) score += this.weightings.deepPath;
    if (features.numericPatterns) score += this.weightings.numericPatterns;
    if (features.subdomains >= 3) score += this.weightings.manySubdomains;
    return Math.min(100, score);
  }
  /**
   * Classifies the risk of a given URL string by extracting features, calculating a risk score, and determining a risk level (LOW, MEDIUM, HIGH).
   * @param {string} urlString - The URL string to classify.
   * @returns {Object} - An object containing the risk score, risk level, and extracted features.
   */
  classifyRisk(urlString) {
    const features = this.extractFeatures(urlString);
    const score = this.calculateRiskScore(features);
    let level = "LOW";
    if (score >= 70) level = "HIGH";
    else if (score >= 30) level = "MEDIUM";
    return { score, level, features };
  }
}

/**
 *  RedirectChainAnalyser tracks redirect chains for each browser tab and evaluates them to detect suspicious behavior based on the number of hops and unique domains involved.
 */
class RedirectChainAnalyser { 
  /**
   * constructor initializes the RedirectChainAnalyser with a map to track redirect chains by tab ID and a suppression threshold for flagging suspicious chains.
   */
  constructor() {
    this.chainsByTab = new Map(); // tabId -> [{from, to, ts}]
    this.suppressionThreshold = 3;
  }
/** 
 * Records a redirect hop for a given tab, storing the source and destination URLs along with a timestamp. It also maintains only the last 15 seconds of hops to approximate a single interaction.
 */
  recordHop(tabId, from, to) { 
    // Initialize the chain for the tab if it doesn't exist yet.
    if (!this.chainsByTab.has(tabId)) this.chainsByTab.set(tabId, []);
    const chain = this.chainsByTab.get(tabId);
    chain.push({ from, to, ts: Date.now() });
    // Keep only the last 15s of hops to approximate "a single interaction"
    const cutoff = Date.now() - 15000;
    while (chain.length && chain[0].ts < cutoff) chain.shift(); 
    // Return the current chain for potential further analysis or logging.
    return chain;
  }
/**
 * Evaluates the redirect chain for a given tab to determine if it is suspicious based on the number of hops and unique domains involved. If the chain exceeds the suppression threshold, it is flagged as suspicious.
 * @param {number} tabId - The ID of the browser tab to evaluate.
 * @returns {Object} - An object containing the evaluation results, including whether the chain is flagged, the hop count, unique domains, and the full chain.
*/
  evaluateChain(tabId) { 
    // Retrieve the redirect chain for the specified tab ID, or use an empty array if no chain exists.
    const chain = this.chainsByTab.get(tabId) || [];
    const uniqueDomains = new Set(); 
    // Iterate through each hop in the chain and extract the hostname from the destination URL, adding it to the set of unique domains. If the URL is invalid, it is ignored.
    for (const hop of chain) {
      try {
        uniqueDomains.add(new URL(hop.to).hostname);
      } catch {
        /* ignore */
      }
    } 
    // Determine the number of hops in the chain and check if it exceeds the suppression threshold. If it does, return an object indicating that the chain is flagged as suspicious, along with the hop count, unique domains, and the full chain. Otherwise, return an object indicating that the chain is not flagged.
    const hopCount = chain.length;
    if (hopCount >= this.suppressionThreshold) {
      return {
        flagged: true,
        hopCount,
        domains: [...uniqueDomains],
        chain: [...chain],
      };
    }
    return { flagged: false, hopCount, domains: [...uniqueDomains], chain: [...chain] };
  }

  clear(tabId) {
    this.chainsByTab.delete(tabId);
  }
}

/**
 * AdNetworkRegistry manages a list of known ad-serving domains and provides methods to synchronize declarativeNetRequest rules for blocking ads on specific sites based on user preferences.
 */
const AdNetworkRegistry = {
  // List of known ad-serving domains that can be blocked by the extension. This list is used to create declarativeNetRequest rules for blocking ads on specific sites.
  DOMAINS: [
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    "amazon-adsystem.com",
    "adnxs.com",
    "adnxs-simple.com",
    "criteo.com",
    "criteo.net",
    "taboola.com",
    "outbrain.com",
    "media.net",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",
    "indexexchange.com",
    "adform.net",
    "smartadserver.com",
    "adroll.com",
    "bidswitch.net",
    "contextweb.com",
    "sharethrough.com",
    "teads.tv",
    "sovrn.com",
    "connatix.com",
    "moatads.com",
    "adsrvr.org",
    "yieldmo.com",
    "gumgum.com",
    "33across.com",
    "adcolony.com",
    "mgid.com",
    "revcontent.com",
    "propellerads.com",
    "popads.net",
    "adskeeper.co.uk",
    // Pop-under / malicious ad networks (added for sites like yourbittorrent.com)
    "zap.buzz",
    "wpadmngr.com",
    "tuckerclassesjackal.com",
    "adcash.com",
    "aclibsa.com",
    "aclib.com",
    "popcash.net",
    "clickadu.com",
    "trafficfactory.biz",
    "onclickads.net",
    "adsterra.com",
    "exoclick.com",
    "juicyads.com",
    "plugrush.com",
    "hilltopads.net",
    "royalads.net",
  ],
  /**
   * Generates the next unique rule ID for declarativeNetRequest rules, ensuring that each rule has a distinct identifier.
   * @returns {Promise<number>} - A promise that resolves to the next unique rule ID.
   */
  async _nextRuleId() {
    const key = "dnr:nextAdRuleId";
    const r = await chrome.storage.local.get(key);
    const id = r[key] || 100000;
    await chrome.storage.local.set({ [key]: id + 1 });
    return id;
  },

  /** 
   * Synchronizes the declarativeNetRequest rules for a specific site based on the user's filtering mode. If the mode is "BLOCK_ALL", it adds rules to block known ad-serving domains for that site. If the mode is not "BLOCK_ALL", it removes any existing rules for that site.
   * @param {string} url - The URL of the site for which to synchronize rules.
   * @param {string} mode - The filtering mode for the site ("BLOCK_ALL" or other).
   */
  async syncForSite(url, mode) { 
    // Normalize the domain from the provided URL and generate a unique site ID for storage and rule management.
    const domain = normaliseDomain(url);
    const siteId = hashId(domain);
    const storeKey = `adrules:${siteId}`; 
    // Retrieve any existing rule IDs for the site from chrome.storage.local. If there are existing rules, remove them from declarativeNetRequest and clear the stored rule IDs.
    const existing = (await chrome.storage.local.get(storeKey))[storeKey] || [];
    // If there are existing rules for the site, remove them from declarativeNetRequest and clear the stored rule IDs in chrome.storage.local.
    if (existing.length) {
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: existing }).catch(() => {});
      await chrome.storage.local.remove(storeKey);
    }
  // If the filtering mode is not "BLOCK_ALL" or the domain is "global-default", return early without adding new rules. This ensures that rules are only added for sites where the user has explicitly chosen to block all ads.
    if (mode !== "BLOCK_ALL" || domain === "global-default") return;

    const addRules = [];
    const newIds = []; 
    // For each known ad-serving domain, generate a new unique rule ID and create a declarativeNetRequest rule to block requests to that domain when initiated from the specified site. The rules are configured to block various resource types, including scripts, sub-frames, images, XMLHttpRequests, media, pings, and other types of requests.
    for (const adDomain of this.DOMAINS) {
      const id = await this._nextRuleId();
      newIds.push(id);
      addRules.push({
        id,
        priority: 1,
        action: { type: "block" },
        condition: {
          requestDomains: [adDomain],
          initiatorDomains: [domain],
          resourceTypes: ["script", "sub_frame", "image", "xmlhttprequest", "media", "ping", "other"],
        },
      });
    }

    await chrome.declarativeNetRequest.updateDynamicRules({ addRules }).catch((e) => {
      console.warn("Safe-web: failed to register BLOCK_ALL ad rules", e);
    });
    await chrome.storage.local.set({ [storeKey]: newIds });
  },

  /**
   * Reconciles the declarativeNetRequest rules for all sites based on the user's saved preferences. It retrieves all site preferences from the SitePreferenceStore and synchronizes the rules for sites that have the "BLOCK_ALL" filtering mode.
   * @param {SitePreferenceStore} preferenceStore - The SitePreferenceStore instance used to retrieve site preferences.
   */
  async reconcileAll(preferenceStore) {
    const prefs = await preferenceStore.listAll();
    for (const pref of prefs) {
      if (pref.filterMode === "BLOCK_ALL") {
        await this.syncForSite(pref.domain, "BLOCK_ALL");
      }
    }
  },
};

// ============================================================
// SitePreferenceStore (User Control Layer)
// ============================================================
class SitePreferenceStore {
  async save(url, mode) {
    const domain = normaliseDomain(url);
    const siteId = hashId(domain);
    const pref = {
      siteId,
      domain,
      filterMode: mode,
      savedAt: nowISO(),
      isGlobal: false,
    };
    await chrome.storage.local.set({ [`pref:${siteId}`]: pref });
    await AdNetworkRegistry.syncForSite(url, mode);
    return pref;
  }

  async load(url) {
    const domain = normaliseDomain(url);
    const siteId = hashId(domain);
    const result = await chrome.storage.local.get(`pref:${siteId}`);
    return result[`pref:${siteId}`] || null;
  }

  async listAll() {
    const all = await chrome.storage.local.get(null);
    return Object.entries(all)
      .filter(([k]) => k.startsWith("pref:"))
      .map(([, v]) => v);
  }

  async delete(url) {
    const domain = normaliseDomain(url);
    const siteId = hashId(domain);
    await chrome.storage.local.remove(`pref:${siteId}`);
  }
}

// ============================================================
// WhitelistManager (User Control Layer)
// ============================================================
class WhitelistManager {
  async addNetwork(domain) {
    const clean = normaliseDomain(domain);
    const whitelistId = hashId(clean);
    const entry = {
      whitelistId,
      domain: clean,
      addedAt: nowISO(),
      addedBy: "USER",
    };
    await chrome.storage.local.set({ [`wl:${whitelistId}`]: entry });
    return entry;
  }

  async removeNetwork(domain) {
    const clean = normaliseDomain(domain);
    const whitelistId = hashId(clean);
    await chrome.storage.local.remove(`wl:${whitelistId}`);
  }

  async isTrustedDomain(domain) {
    const clean = normaliseDomain(domain);
    const all = await this.listNetworks();
    return all.some((e) => clean === e.domain || clean.endsWith("." + e.domain));
  }

  async listNetworks() {
    const all = await chrome.storage.local.get(null);
    return Object.entries(all)
      .filter(([k]) => k.startsWith("wl:"))
      .map(([, v]) => v);
  }
}

// ============================================================
// FilteringModeEngine (User Control Layer)
// ============================================================
class FilteringModeEngine {
  constructor(preferenceStore, whitelistManager) {
    this.preferenceStore = preferenceStore;
    this.whitelistManager = whitelistManager;
  }

  async getModeForSite(url) {
    const pref = await this.preferenceStore.load(url);
    return pref ? pref.filterMode : null;
  }

  async applyFilteringMode(mode, url) {
    await this.preferenceStore.save(url, mode);
    return mode;
  }

  /**
   * Decide the ActionType for a detected ThreatEvent, honouring the
   * whitelist override and the site's active FilterMode.
   * @returns {"BLOCKED"|"ALLOWED"|"LOGGED_ONLY"}
   */
  async evaluateThreatEvent(threatEvent, siteUrl) {
    let targetDomain;
    try {
      targetDomain = new URL(threatEvent.affectedURL).hostname;
    } catch {
      targetDomain = threatEvent.affectedURL;
    }

    if (await this.whitelistManager.isTrustedDomain(targetDomain)) {
      return "ALLOWED";
    }

    const mode = (await this.getModeForSite(siteUrl)) || "FILTER_ONLY";

    if (mode === "ALLOW_ALL") return "LOGGED_ONLY";
    if (mode === "BLOCK_ALL") return "BLOCKED";

    // FILTER_ONLY: block only if risk is meaningfully elevated
    if (threatEvent.riskScore >= 50) return "BLOCKED";
    return "LOGGED_ONLY";
  }

  async shouldBlockAd(threatEvent, siteUrl) {
    const action = await this.evaluateThreatEvent(threatEvent, siteUrl);
    return action === "BLOCKED";
  }
}

/**
 * SessionThreatLog manages the logging of detected threats during a browsing session. It records threat events, including their type, affected URL, risk score, and the action taken (blocked, allowed, or logged only). The log entries are stored in chrome.storage.local and can be retrieved or cleared as needed. The class also provides a method to convert threat events into plain language summaries for user-friendly reporting.  
 */
const PLAIN_LANGUAGE = {
  MALICIOUS_JS_REDIRECT: "A script tried to secretly redirect you to another site.",
  SUSPICIOUS_IFRAME: "A hidden frame from an unfamiliar site was found on this page.",
  REDIRECT_CHAIN: "Clicking led through several unexpected sites in a row.",
  MALICIOUS_URL: "A link on this page had the hallmarks of a malicious address.",
  BLOCKLIST_MATCH: "This request went to a domain known for malicious ads.",
  FAKE_POPUP_ALERT: "A fake system warning tried to scare you into calling a number.",
  AD_DETECTED: "An advertisement from a known ad network was found on this page.",
  POPUP_WINDOW_BLOCKED: "A pop-up window was opened without you clicking anything.",
  AD_POPUP_OVERLAY: "A full-screen ad covered the page without opening a new tab or window.",
};
/**
 * 
 * @class SessionThreatLog
 */
class SessionThreatLog { 
  /**
   * Adds a new threat event entry to the session log. The entry includes details such as the site ID, session ID, threat type, affected URL, risk score, action taken, filtering mode, and a plain language summary. The entry is stored in chrome.storage.local under a key specific to the current browsing session. If the action taken is not "ALLOWED", the badge notification count is incremented.
   * @param {Object} event - The threat event object containing details about the detected threat.
   * @returns {Promise<Object>} - A promise that resolves to the newly added log entry.
   */
  async addEntry(event) {
    const session = await BrowsingSession.current();
    const entryId = uuidv4();
    const entry = {
      entryId,
      siteId: hashId(normaliseDomain(event.siteUrl || event.affectedURL || "")),
      sessionId: session.sessionId,
      threatType: event.threatType,
      affectedURL: event.affectedURL,
      affectedElement: event.affectedElement || null,
      riskScore: event.riskScore,
      actionTaken: event.actionTaken,
      filteringMode: event.filteringMode || "FILTER_ONLY",
      plainLanguageSummary: this.toPlainLanguage(event),
      timestamp: nowISO(),
    };

    const key = `log:${session.sessionId}`;
    const existing = (await chrome.storage.local.get(key))[key] || [];
    existing.unshift(entry); // reverse-chronological, per FR-10
    await chrome.storage.local.set({ [key]: existing });
// Increment the badge count if the action taken is not "ALLOWED".
    if (entry.actionTaken !== "ALLOWED") {
      await BadgeNotificationService.increment();
    }
    return entry;
  }

  async getEntries(sessionId) {
    const sid = sessionId || (await BrowsingSession.current()).sessionId;
    const key = `log:${sid}`;
    return (await chrome.storage.local.get(key))[key] || [];
  }

  async clear(sessionId) {
    const sid = sessionId || (await BrowsingSession.current()).sessionId;
    await chrome.storage.local.remove(`log:${sid}`);
    await BadgeNotificationService.reset();
  }
 /**
  * Converts a threat event into a plain language summary for user-friendly reporting. It uses predefined messages based on the threat type and includes the source domain if available.
  * @param {Object} event - The threat event object containing details about the detected threat.
  * @returns {string} - A plain language summary of the threat event.
  */
  toPlainLanguage(event) { 
    // Use a predefined message based on the threat type, or a default message if the threat type is not recognized.
    const base = PLAIN_LANGUAGE[event.threatType] || "Suspicious advertising activity was detected.";
    let domain = null;
    try {
      domain = new URL(event.affectedURL).hostname;
    } catch {
      // ignore
    }
    return domain ? `${base} Source: ${domain}` : base;
  }
}

/**
 * BadgeNotificationService manages the badge count displayed on the extension's icon in the browser toolbar. It provides methods to increment, reset, and retrieve the badge count, as well as to render the badge with the appropriate text and background color. The badge count is stored in chrome.storage.session and is updated whenever a new threat event is logged or when the user clears the log.
 */
const BadgeNotificationService = {
  async incrementBadge() {
    return this.increment();
  },
  async increment() {
    const count = (await this.getBadgeCount()) + 1;
    await chrome.storage.session.set({ badgeCount: count });
    await this._render(count);
    return count;
  },
  async resetBadge() {
    return this.reset();
  },
  async reset() {
    await chrome.storage.session.set({ badgeCount: 0 });
    await this._render(0);
  }, 
  /**
   * Retrieves the current badge count from chrome.storage.session. If the badge count is not set, it defaults to 0.
   * @returns {Promise<number>} - A promise that resolves to the current badge count.
   */
  async getBadgeCount() {
    const r = await chrome.storage.session.get("badgeCount");
    return r.badgeCount || 0;
  }, 
  /**
   * Renders the badge with the specified count. If the count is greater than 0, it displays the count (capped at 99) on the badge with a red background. If the count is 0, it clears the badge text. The badge text color is set to white if supported by the browser.
   * @param {number} count - The count to display on the badge.
   */
  async _render(count) {
    const text = count > 0 ? String(Math.min(count, 99)) : "";
    await chrome.action.setBadgeText({ text }); 
    // Set the badge background color to red (#e63946) to indicate a warning or alert state.
    await chrome.action.setBadgeBackgroundColor({ color: "#e63946" });
    if (chrome.action.setBadgeTextColor) {
      try { 
        //
        await chrome.action.setBadgeTextColor({ color: "#ffffff" });
      } catch {
        // ignore; not supported in all browsers
      }
    }
  },
};
/**
 * BrowsingSession manages the current browsing session, including starting a new session, retrieving the current session, and storing session-related data in chrome.storage.session. Each session has a unique session ID, a start timestamp, an optional end timestamp, and a badge count for tracking the number of threat events logged during the session.
  */

const BrowsingSession = { 
  /**
   * Retrieves the current browsing session from chrome.storage.session. If a session exists, it returns the session object. If no session exists, it starts a new session and returns the newly created session object.
   * @returns {Promise<Object>} - A promise that resolves to the current browsing session object.
   */
  async current() {
    const r = await chrome.storage.session.get("session");
    if (r.session) return r.session;
    return this.start();
  }, 
  /**
   * Starts a new browsing session by generating a unique session ID, recording the start timestamp, initializing the badge count to 0, and storing the session data in chrome.storage.session and chrome.storage.local. It returns the newly created session object.
   * @returns {Promise<Object>} - A promise that resolves to the newly created browsing session object.
   */
  async start() {
    const session = {
      sessionId: uuidv4(),
      sessionStart: nowISO(),
      sessionEnd: null,
      badgeCount: 0,
    };
    await chrome.storage.session.set({ session });
    await chrome.storage.local.set({ "session:current": session });
    return session;
  },
};

/**
 * Initialize the core components of the Safe-web extension, including the blocklist matcher, URL classifier, redirect chain analyser, site preference store, whitelist manager, filtering mode engine, and session threat log. These components work together to detect and manage threats during browsing sessions, enforce user-defined filtering modes, and provide notifications for critical threats.
 */
const blocklistMatcher = new BlocklistMatcher();
const urlClassifier = new URLClassifier();
const redirectAnalyser = new RedirectChainAnalyser();
const preferenceStore = new SitePreferenceStore();
const whitelistManager = new WhitelistManager();
const filteringEngine = new FilteringModeEngine(preferenceStore, whitelistManager);
const sessionLog = new SessionThreatLog();

/**
 * DetectionEngine serves as the central entry point for content scripts to report detected threats. It evaluates the threat event using the filtering engine, logs the event in the session log, and triggers notifications for critical threats. The engine supports all networks and maintains a running state.
 */
const DetectionEngine = { 
  // currently running state of the detection engine, indicating whether it is actively processing threat events.
  isRunning: true,
  supportedNetworks: ["*"],

  /** Central entry point content scripts call (via message) after local detection. */
  async classifyAndLog(threatEvent, siteUrl) {
    const action = await filteringEngine.evaluateThreatEvent(threatEvent, siteUrl);
    threatEvent.actionTaken = action;
    threatEvent.siteUrl = siteUrl;
    const mode = (await filteringEngine.getModeForSite(siteUrl)) || "FILTER_ONLY";
    threatEvent.filteringMode = mode;
    const entry = await sessionLog.addEntry(threatEvent);
    // Trigger a notification for critical threats (risk score >= 80) to alert the user. The notification includes an icon, title, message, and priority level.
    if (threatEvent.riskScore >= 80) {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "Safe-web: Critical threat blocked",
        message: entry.plainLanguageSummary,
        priority: 2,
      });
    }
    return entry;
  },
};

// ============================================================
// Lifecycle: startup and install
// ============================================================
async function refreshBlocklistFromRemote() {
  const domains = await fetchRemoteBlocklist();
  if (domains) {
    await blocklistMatcher.loadBlocklist(domains);
    console.log(`Safe-web: loaded ${domains.length} domains from uBlock Origin badware.txt`);
  } else {
    // No network yet / fetch failed — make sure something is loaded regardless.
    if (blocklistMatcher.getEntryCount() === 0) {
      await blocklistMatcher.loadBlocklist(); // falls back to SEED_DOMAINS
    }
  }
}
/**
 * Handles the extension's startup event by initializing the browsing session, resetting the badge notification count, loading the blocklist, and refreshing the blocklist from a remote source. This ensures that the extension is ready to protect the user as soon as the browser starts.
 */
chrome.runtime.onStartup.addListener(async () =>  { 
  // Initialize the browsing session and reset the badge notification count to ensure a clean state at startup.
  await BrowsingSession.start();
  await BadgeNotificationService.reset();
  try {
    await blocklistMatcher.loadBlocklist(); // seed list immediately, so protection is live at once
  } catch (e) {
    console.error("Safe-web: loadBlocklist() failed on startup — falling back to whatever is already loaded", e);
  }
  refreshBlocklistFromRemote(); // then upgrade to the real feed in the background
});
/**
 * Handles the extension's installation event by initializing the browsing session, resetting the badge notification count, loading the blocklist, setting default global settings, creating a daily alarm to refresh the blocklist, and reconciling ad network rules. This ensures that the extension is properly set up and ready to protect the user immediately after installation.
 */
chrome.runtime.onInstalled.addListener(async () => {
  await BrowsingSession.start();
  await BadgeNotificationService.reset();
  try {
    await blocklistMatcher.loadBlocklist(); // seed list immediately
  } catch (e) {
    console.error("Safe-web: loadBlocklist() failed on install - continuing with remaining setup", e);
  } 
  // Set default global settings for the extension, including filter mode, version, and onboarding status.
  await chrome.storage.local.set({
    "settings:global": { filterMode: "FILTER_ONLY", version: "1.0.0", onboarded: false },
  });
  chrome.alarms.create("refreshBlocklist", { periodInMinutes: 1440 });
  refreshBlocklistFromRemote(); // then upgrade to the real feed in the background 
  // Reconcile ad network rules to restore BLOCK_ALL ad rules across sites based on user preferences.
  try {
    await AdNetworkRegistry.reconcileAll(preferenceStore); // restore BLOCK_ALL ad rules across sites
  } catch (e) {
    console.error("Safe-web: AdNetworkRegistry.reconcileAll() failed on install", e);
  }
});
/**
 * Handles the alarm event for refreshing the blocklist. When the "refreshBlocklist" alarm is triggered, it calls the refreshBlocklistFromRemote function to fetch and update the blocklist from a remote source. This ensures that the extension maintains an up-to-date list of malicious domains for effective threat detection.
 */
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "refreshBlocklist") {
    await refreshBlocklistFromRemote();
  }
});

// Ensure the blocklist Trie is warm even on a cold service-worker wake.
blocklistMatcher.loadBlocklist().catch((e) =>
  console.error("Safe-web: loadBlocklist() failed on cold wake", e)
);


/**
 * Handles the onBeforeRedirect event for web requests. When a redirect occurs, it records the redirect hop in the RedirectChainAnalyser for the corresponding tab. This allows the extension to track redirect chains and evaluate them for suspicious behavior.
 */
chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.tabId < 0) return;
    redirectAnalyser.recordHop(details.tabId, details.url, details.redirectUrl);
  },
  { urls: ["<all_urls>"] }
);
// Evaluate each request against the blocklist, and log any matches as a threat event.
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => { 
    // Ignore requests that are not associated with a valid tab or are for the main frame, as these are not relevant for blocklist matching.
    if (details.tabId < 0 || details.type === "main_frame") return;
    let hostname;
    try {
      hostname = new URL(details.url).hostname;
    } catch {
      return;
    }
     // Check if the hostname of the request matches any entry in the blocklist. If a match is found, retrieve the tab information and log a threat event with details about the blocked request, including the threat type, risk score, affected URL, and affected element (if applicable). The threat event is then classified and logged using the DetectionEngine. 
    if (blocklistMatcher.lookup(hostname)) { 
      // If the hostname is found in the blocklist, retrieve the tab information for the request. If the tab information is successfully retrieved, use the tab's URL as the site URL for logging the threat event. If the tab information cannot be retrieved (e.g., if the tab has been closed), fall back to using the request's URL as the site URL.
      const tab = await chrome.tabs.get(details.tabId).catch(() => null);
      const siteUrl = tab?.url || details.url;
      const threatEvent = {
        threatType: "BLOCKLIST_MATCH",
        riskScore: 90,
        affectedURL: details.url, 
        affectedElement: null,
      }; 
      // Classify and log the threat event using the DetectionEngine, which evaluates the threat and records it in the session log.
      DetectionEngine.classifyAndLog(threatEvent, siteUrl);
    }
  },
  { urls: ["<all_urls>"] }
);

// Evaluate redirect chains shortly after each redirect settles.
chrome.webRequest.onCompleted.addListener(
  async (details) => {
    if (details.tabId < 0) return;
    const result = redirectAnalyser.evaluateChain(details.tabId);
    if (result.flagged) {
      const tab = await chrome.tabs.get(details.tabId).catch(() => null);
      const siteUrl = tab?.url;
      if (!siteUrl) return;
      const threatEvent = {
        threatType: "REDIRECT_CHAIN",
        riskScore: Math.min(100, 40 + result.hopCount * 12),
        affectedURL: details.url,
        affectedElement: `${result.hopCount}-hop chain via ${result.domains.join(" \u2192 ")}`,
      };
      await DetectionEngine.classifyAndLog(threatEvent, siteUrl);
      redirectAnalyser.clear(details.tabId);
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.tabs.onRemoved.addListener((tabId) => redirectAnalyser.clear(tabId));

/**
 * Handles messages sent to the background script from content scripts or other parts of the extension. It listens for various message types, such as threat events, preference checks, preference saves, mode retrievals, whitelist management, log retrievals, and badge count requests. Depending on the message type, it performs the appropriate action and sends a response back to the sender.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    const siteUrl = message.siteUrl || sender.tab?.url;

    switch (message.type) {
      case "THREAT_EVENT": {
        // Optionally enrich with URL risk scoring before logging.
        if (message.threatType === "MALICIOUS_URL" && message.affectedURL) {
          const { score } = urlClassifier.classifyRisk(message.affectedURL);
          message.riskScore = Math.max(message.riskScore || 0, score);
        }
        const entry = await DetectionEngine.classifyAndLog(message, siteUrl);
        sendResponse({ ok: true, entry });
        break;
      }
   // Check if this is the first visit to the site by loading the user's preference for the site. If no preference is found, it indicates that this is the first visit. The response includes whether it is the first visit and the current filtering mode for the site (if any).
      case "CHECK_FIRST_VISIT": {
        const pref = await preferenceStore.load(siteUrl);
        sendResponse({ ok: true, isFirstVisit: !pref, mode: pref?.filterMode || null });
        break;
      }
    // Save the user's preference for the site by storing the filtering mode in the SitePreferenceStore. After saving the preference, it synchronizes the ad network rules for the site based on the selected filtering mode. The response includes the saved preference details.
      case "SAVE_PREFERENCE": {
        const pref = await preferenceStore.save(message.url, message.mode);
        sendResponse({ ok: true, pref });
        break;
      }
// Retrieve the current filtering mode for the site by loading the user's preference from the SitePreferenceStore. If no preference is found, it defaults to "FILTER_ONLY". The response includes the current filtering mode for the site.
      case "GET_MODE_FOR_SITE": {
        const mode = await filteringEngine.getModeForSite(message.url || siteUrl);
        sendResponse({ ok: true, mode: mode || "FILTER_ONLY" });
        break;
      }
     // Apply the user's selected filtering mode for the site by saving the preference in the SitePreferenceStore and synchronizing the ad network rules. The response includes the applied filtering mode.
      case "GET_AD_DOMAINS": {
        sendResponse({ ok: true, domains: AdNetworkRegistry.DOMAINS });
        break;
      }
     // Check if a given domain is in the user's whitelist by calling the isTrustedDomain method of the WhitelistManager. The response includes whether the domain is trusted (i.e., in the whitelist).
      case "IS_TRUSTED_DOMAIN": {
        const trusted = await whitelistManager.isTrustedDomain(message.domain);
        sendResponse({ ok: true, trusted });
        break;
      }
  // Retrieve the log entries for the current browsing session by calling the getEntries method of the SessionThreatLog. The response includes the log entries, which contain details about detected threats and actions taken.
      case "GET_LOG_ENTRIES": {
        const entries = await sessionLog.getEntries();
        sendResponse({ ok: true, entries });
        break;
      }
  // Clear the log entries for the current browsing session by calling the clear method of the SessionThreatLog. The response indicates that the log has been cleared successfully.
      case "CLEAR_LOG": {
        await sessionLog.clear();
        sendResponse({ ok: true });
        break;
      }
  // Retrieve the current badge count by calling the getBadgeCount method of the BadgeNotificationService. The response includes the current badge count, which indicates the number of threat events logged during the session.
      case "GET_BADGE_COUNT": {
        const count = await BadgeNotificationService.getBadgeCount();
        sendResponse({ ok: true, count });
        break;
      }
   // Manage the user's whitelist by handling requests to list, add, or remove domains from the whitelist. The WhitelistManager is used to perform these operations, and the response includes the results of the requested action.
      case "LIST_WHITELIST": {
        const list = await whitelistManager.listNetworks();
        sendResponse({ ok: true, list });
        break;
      }
    // Add a domain to the user's whitelist by calling the addNetwork method of the WhitelistManager. The response includes the newly added whitelist entry, which contains details about the domain and when it was added.
      case "ADD_WHITELIST": {
        const entry = await whitelistManager.addNetwork(message.domain);
        sendResponse({ ok: true, entry });
        break;
      }
    // Remove a domain from the user's whitelist by calling the removeNetwork method of the WhitelistManager. The response indicates that the domain has been successfully removed from the whitelist.
      case "REMOVE_WHITELIST": {
        await whitelistManager.removeNetwork(message.domain);
        sendResponse({ ok: true });
        break;
      }
    // Trigger a rescan of the current active tab by sending a message to the content script in that tab. The content script is expected to handle the "TRIGGER_RESCAN" message and perform the necessary actions to re-evaluate the page for threats. The response indicates that the rescan request has been sent successfully.
      case "RESCAN": {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs[0]?.id) { 
          // Send a message to the content script in the active tab to trigger a rescan of the page for threats. The content script should handle the "TRIGGER_RESCAN" message and perform the necessary actions to re-evaluate the page.
          chrome.tabs.sendMessage(tabs[0].id, { type: "TRIGGER_RESCAN" }).catch(() => {});
        }
        sendResponse({ ok: true });
        break;
      }
    // Retrieve information about the currently active tab, including its URL and title. The response includes the URL and title of the active tab, or null if the information cannot be retrieved.
      case "GET_ACTIVE_TAB_INFO": { 
        // Retrieve the currently active tab in the current window using chrome.tabs.query. The query filters for the active tab in the current window, and the first tab in the resulting array is used to extract its URL and title.
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const tab = tabs[0];
        sendResponse({
          ok: true,
          url: tab?.url || null,
          title: tab?.title || null,
        });
        break;
      }
  // Handle any unknown message types by sending an error response indicating that the message type is not recognized. This ensures that the sender is informed of unsupported or invalid requests.
      default:
        sendResponse({ ok: false, error: "Unknown message type" });
    }
  })();
  return true; // keep the message channel open for the async response
});