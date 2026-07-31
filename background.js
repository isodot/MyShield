// Background service worker equivalent for Manifest V2. This script keeps the
// blocklists, stats, protection toggles, and strict-mode state in memory and storage.
(() => {
  const BLOCKLIST_URLS = {
    ads: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    malware: "https://urlhaus.abuse.ch/downloads/hostfile/"
  };
  const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
  const DEFAULT_STATS = {
    ads: 0,
    malware: 0,
    popups: 0,
    tabs: 0,
    downloads: 0,
    adRedirects: 0
  };

  let enabled = true;
  let stats = { ...DEFAULT_STATS };
  let blockedDomains = new Set();
  let domainCategories = new Map();
  let allowedPopupDomains = new Set();
  let trustedDownloadDomains = new Set();
  let strictModeDomains = new Set();
  let blocklistTimestamp = 0;
  let strictModeTabs = new Map();
  let pendingCrossDomainClicks = new Map();

  function normalizeDomain(value) {
    if (!value) {
      return "";
    }

    try {
      return value.trim().toLowerCase().replace(/^www\./, "");
    } catch (error) {
      console.warn("MyShield: unable to normalize domain", error);
      return "";
    }
  }

  function extractHostname(url) {
    if (!url) {
      return "";
    }

    try {
      const parsed = new URL(url);
      return parsed.hostname.toLowerCase();
    } catch (error) {
      return "";
    }
  }

  function getBaseDomain(hostname) {
    if (!hostname) {
      return "";
    }

    try {
      const parts = hostname.split('.').filter(Boolean);
      if (parts.length <= 1) {
        return hostname;
      }

      const publicSuffixes = new Set([
        "com", "org", "net", "edu", "gov", "uk", "co.uk", "ac.uk", "com.au",
        "co.jp", "jp", "fr", "ca", "io", "ai", "dev", "app", "blog", "tv",
        "me", "info", "ru", "cn", "co", "in", "us", "nz", "br", "eu", "it",
        "es", "pl", "de", "cz", "sk", "xyz", "online", "site", "club"
      ]);

      for (let index = parts.length - 2; index >= 0; index -= 1) {
        const candidate = parts.slice(index).join('.');
        const suffix = parts.slice(index + 1).join('.');
        if (publicSuffixes.has(candidate) || publicSuffixes.has(suffix)) {
          return parts.slice(index - 1 >= 0 ? index - 1 : index).join('.');
        }
      }

      return parts.slice(-2).join('.');
    } catch (error) {
      return "";
    }
  }

  function isLocalOrPrivateHost(hostname) {
    if (!hostname) {
      return true;
    }

    const host = hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "::1") {
      return true;
    }

    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      const parts = host.split('.').map(Number);
      return parts[0] === 10 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168);
    }

    return false;
  }

  function isIpAddress(value) {
    return /^\d+\.\d+\.\d+\.\d+$/.test(value);
  }

  async function saveState() {
    try {
      await browser.storage.local.set({
        enabled,
        stats,
        blocklistTimestamp,
        domainCategories: Object.fromEntries(domainCategories),
        allowedPopupDomains: Array.from(allowedPopupDomains),
        trustedDownloadDomains: Array.from(trustedDownloadDomains),
        strictModeDomains: Array.from(strictModeDomains)
      });
    } catch (error) {
      console.warn("MyShield: failed to persist state", error);
    }
  }

  async function restoreState() {
    try {
      const stored = await browser.storage.local.get([
        "enabled",
        "stats",
        "blocklistTimestamp",
        "domainCategories",
        "allowedPopupDomains",
        "trustedDownloadDomains",
        "strictModeDomains"
      ]);

      enabled = stored.enabled !== undefined ? stored.enabled : true;
      stats = { ...DEFAULT_STATS, ...(stored.stats || {}) };
      blocklistTimestamp = stored.blocklistTimestamp || 0;
      allowedPopupDomains = new Set((stored.allowedPopupDomains || []).map(normalizeDomain));
      trustedDownloadDomains = new Set((stored.trustedDownloadDomains || []).map(normalizeDomain));
      strictModeDomains = new Set((stored.strictModeDomains || []).map(normalizeDomain));

      const restoredCategories = stored.domainCategories || {};
      domainCategories = new Map(Object.entries(restoredCategories));
      blockedDomains = new Set(Object.keys(restoredCategories));
    } catch (error) {
      console.warn("MyShield: failed to restore state", error);
    }
  }

  function mergeCategory(existingCategory, newCategory) {
    if (!existingCategory) {
      return newCategory;
    }
    if (existingCategory === newCategory) {
      return existingCategory;
    }
    return "mixed";
  }

  function parseHostsFile(text, category) {
    const parsed = new Map();

    if (!text) {
      return parsed;
    }

    const lines = text.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        continue;
      }

      const parts = trimmed.split(/\s+/);
      if (parts.length < 2) {
        continue;
      }

      const address = parts[0];
      const candidate = parts[parts.length - 1].replace(/\.$/, "");
      if (!candidate || candidate.startsWith("#") || !isIpAddress(address)) {
        continue;
      }

      const domain = normalizeDomain(candidate);
      if (!domain) {
        continue;
      }

      const existing = parsed.get(domain);
      parsed.set(domain, mergeCategory(existing, category));
    }

    return parsed;
  }

  async function fetchAndParseBlocklist(url, category) {
    try {
      const response = await fetch(url, { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`Request failed with ${response.status}`);
      }
      const text = await response.text();
      return parseHostsFile(text, category);
    } catch (error) {
      console.warn(`MyShield: unable to fetch ${category} blocklist`, error);
      return new Map();
    }
  }

  async function refreshBlocklists(force = false) {
    const now = Date.now();
    const isFresh = !force && blocklistTimestamp > 0 && (now - blocklistTimestamp) < CACHE_TTL_MS;
    if (isFresh) {
      return;
    }

    const [adsMap, malwareMap] = await Promise.all([
      fetchAndParseBlocklist(BLOCKLIST_URLS.ads, "ads"),
      fetchAndParseBlocklist(BLOCKLIST_URLS.malware, "malware")
    ]);

    const merged = new Map();
    for (const [domain, category] of adsMap.entries()) {
      const existing = merged.get(domain);
      merged.set(domain, mergeCategory(existing, category));
    }
    for (const [domain, category] of malwareMap.entries()) {
      const existing = merged.get(domain);
      merged.set(domain, mergeCategory(existing, category));
    }

    if (merged.size === 0) {
      const restored = await browser.storage.local.get(["domainCategories"]);
      const fallback = restored.domainCategories || {};
      domainCategories = new Map(Object.entries(fallback));
      blockedDomains = new Set(Object.keys(fallback));
      await saveState();
      return;
    }

    domainCategories = merged;
    blockedDomains = new Set(merged.keys());
    blocklistTimestamp = now;
    await saveState();
  }

  function getCategoriesForHostname(hostname) {
    const host = normalizeDomain(hostname);
    if (!host) {
      return [];
    }

    const categories = [];
    for (const [domain, category] of domainCategories.entries()) {
      if (host === domain || host.endsWith(`.${domain}`)) {
        categories.push(category);
      }
    }
    return categories;
  }

  function incrementStats(category) {
    if (!stats[category]) {
      stats[category] = 0;
    }
    stats[category] += 1;
    saveState().catch(() => {});
  }

  function showNotification(message) {
    try {
      browser.notifications.create({
        type: "basic",
        title: "MyShield",
        message
      });
    } catch (error) {
      console.warn("MyShield: notification failed", error);
    }
  }

  function shouldBlockRequest(url) {
    const hostname = extractHostname(url);
    if (!hostname || !enabled) {
      return null;
    }

    const categories = getCategoriesForHostname(hostname);
    if (categories.length === 0) {
      return null;
    }

    return { hostname, categories };
  }

  function handleBeforeRequest(details) {
    if (!enabled) {
      return {};
    }

    // Block known ad and malware domains before the request completes.
    const blocked = shouldBlockRequest(details.url);
    if (blocked) {
      for (const category of blocked.categories) {
        if (category === "ads" || category === "malware" || category === "mixed") {
          incrementStats(category === "ads" ? "ads" : "malware");
        }
      }
      return { cancel: true };
    }

    // Strict mode can also block cross-domain navigations that happen right after a click.
    if (details.type === "main_frame") {
      const pending = pendingCrossDomainClicks.get(details.tabId);
      if (pending && Date.now() - pending.timestamp < 500) {
        const originHostname = extractHostname(pending.originUrl || "");
        const targetHostname = extractHostname(details.url || "");
        const originBase = getBaseDomain(originHostname);
        const targetBase = getBaseDomain(targetHostname);
        if (originBase && targetBase && originBase !== targetBase) {
          pendingCrossDomainClicks.delete(details.tabId);
          incrementStats("adRedirects");
          browser.tabs.sendMessage(details.tabId, {
            type: "showToast",
            message: `MyShield blocked ad redirect to ${targetBase}`
          }).catch(() => {});
          return { cancel: true };
        }
      }
    }

    const hostname = extractHostname(details.url);
    if (details.url.startsWith("http://") && hostname && !isLocalOrPrivateHost(hostname)) {
      return { redirectUrl: details.url.replace(/^http:\/\//i, "https://") };
    }

    return {};
  }

  async function handleTabCreated(tab) {
    if (!enabled || !tab || typeof tab.openerTabId === "undefined" || tab.openerTabId === -1) {
      return;
    }

    const newUrl = tab.url || tab.pendingUrl || "";
    const newHostname = extractHostname(newUrl);
    const newDomain = getBaseDomain(newHostname);

    try {
      const opener = await browser.tabs.get(tab.openerTabId);
      const openerHostname = extractHostname(opener.url || "");
      const openerDomain = normalizeDomain(openerHostname);
      const openerBase = getBaseDomain(openerHostname);
      const strictModeEnabled = strictModeDomains.has(openerDomain) || strictModeTabs.get(tab.openerTabId);

      if (strictModeEnabled && newDomain && openerBase && newDomain !== openerBase) {
        await browser.tabs.remove(tab.id);
        showNotification(`MyShield blocked a new tab from ${newDomain}`);
        incrementStats("tabs");
        return;
      }

      if (allowedPopupDomains.has(openerBase)) {
        return;
      }

      if (!tab.active) {
        await browser.tabs.remove(tab.id);
        const label = openerBase || "the source site";
        showNotification(`MyShield blocked an auto-opened tab from ${label}`);
        incrementStats("tabs");
      }
    } catch (error) {
      console.warn("MyShield: unable to inspect tab creation", error);
    }
  }

  async function handleDownloadCreated(downloadItem) {
    if (!enabled || !downloadItem) {
      return;
    }

    const hostname = extractHostname(downloadItem.url || "");
    const filename = (downloadItem.filename || "").toLowerCase();
    const dangerousType = /\.(exe|scr|bat|cmd|msi|js|vbs|jar)$/i.test(filename);

    if (blockedDomains.has(hostname)) {
      try {
        await browser.downloads.cancel(downloadItem.id);
        showNotification("MyShield blocked a dangerous download");
        incrementStats("downloads");
      } catch (error) {
        console.warn("MyShield: failed to cancel dangerous download", error);
      }
      return;
    }

    if (dangerousType && !trustedDownloadDomains.has(hostname)) {
      try {
        await browser.downloads.cancel(downloadItem.id);
        showNotification(`MyShield blocked ${filename} from ${hostname}. Add it to trusted domains from the popup to allow it.`);
        incrementStats("downloads");
      } catch (error) {
        console.warn("MyShield: failed to cancel suspicious download", error);
      }
    }
  }

  async function handleMessage(message, sender) {
    if (!message || !message.type) {
      return { ok: false };
    }

    if (message.type === "getStats") {
      const domain = normalizeDomain(message.domain || extractHostname(sender.tab && sender.tab.url ? sender.tab.url : ""));
      return {
        ok: true,
        stats,
        enabled,
        domain,
        strictMode: strictModeDomains.has(domain)
      };
    }

    if (message.type === "toggleProtection") {
      enabled = Boolean(message.value);
      await saveState();
      return { ok: true, enabled };
    }

    if (message.type === "getStrictModeState") {
      const domain = normalizeDomain(message.domain || "");
      return { ok: true, strictMode: strictModeDomains.has(domain) };
    }

    if (message.type === "toggleStrictMode") {
      const domain = normalizeDomain(message.domain || "");
      if (!domain) {
        return { ok: false };
      }
      if (message.value) {
        strictModeDomains.add(domain);
      } else {
        strictModeDomains.delete(domain);
      }
      await saveState();
      return { ok: true, strictMode: strictModeDomains.has(domain), domain };
    }

    if (message.type === "addToWhitelist") {
      const domain = normalizeDomain(message.domain || extractHostname(sender.tab && sender.tab.url ? sender.tab.url : ""));
      if (domain) {
        allowedPopupDomains.add(domain);
        trustedDownloadDomains.add(domain);
        await saveState();
      }
      return { ok: true, domain };
    }

    if (message.type === "setStrictModeState") {
      const domain = normalizeDomain(message.domain || "");
      const entry = { domain, enabled: Boolean(message.value) };
      if (entry.enabled && domain) {
        strictModeTabs.set(sender.tab && sender.tab.id ? sender.tab.id : -1, entry);
      } else if (sender.tab && sender.tab.id) {
        strictModeTabs.delete(sender.tab.id);
      }
      return { ok: true };
    }

    if (message.type === "markNonLinkClick") {
      const tabId = sender.tab && sender.tab.id ? sender.tab.id : -1;
      pendingCrossDomainClicks.set(tabId, {
        timestamp: Date.now(),
        originUrl: sender.tab && sender.tab.url ? sender.tab.url : ""
      });
      return { ok: true };
    }

    if (message.type === "recordStrictModeEvent") {
      if (message.category) {
        incrementStats(message.category);
      }
      return { ok: true };
    }

    if (message.type === "blockPopup") {
      incrementStats("popups");
      return { ok: true };
    }

    if (message.type === "blockDownload") {
      incrementStats("downloads");
      return { ok: true };
    }

    return { ok: false };
  }

  async function init() {
    await restoreState();
    await refreshBlocklists();

    browser.webRequest.onBeforeRequest.addListener(
      handleBeforeRequest,
      { urls: ["<all_urls>"] },
      ["blocking"]
    );

    browser.tabs.onCreated.addListener(handleTabCreated);
    browser.downloads.onCreated.addListener(handleDownloadCreated);
    browser.runtime.onMessage.addListener((message, sender) => handleMessage(message, sender));

    setInterval(() => {
      refreshBlocklists().catch(() => {});
    }, CACHE_TTL_MS);
  }

  init().catch((error) => {
    console.warn("MyShield initialization failed", error);
  });
})();
