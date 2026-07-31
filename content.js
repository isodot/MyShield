// Content script that protects pages from popups and suspicious programmatic
// window opens while still allowing genuine user-triggered navigation.
(() => {
  if (window.__myShieldInjected) {
    return;
  }
  window.__myShieldInjected = true;

  let strictModeActive = false;
  let currentBaseDomain = "";
  let lastUserInteraction = 0;
  let lastMouseDown = 0;
  let observer = null;

  function normalizeDomain(value) {
    if (!value) {
      return "";
    }

    try {
      return value.trim().toLowerCase().replace(/^www\./, "");
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

  function extractHostname(url) {
    if (!url) {
      return "";
    }

    try {
      return new URL(url).hostname.toLowerCase();
    } catch (error) {
      return "";
    }
  }

  function isSameSite(url) {
    if (!url) {
      return false;
    }

    const targetBase = getBaseDomain(extractHostname(url));
    return Boolean(targetBase && currentBaseDomain && targetBase === currentBaseDomain);
  }

  function isDangerousNavigation(url) {
    return /^javascript:/i.test(url) || /^data:/i.test(url);
  }

  function showToast(message) {
    if (!strictModeActive) {
      return;
    }

    const toast = document.createElement("div");
    toast.textContent = message;
    toast.style.position = "fixed";
    toast.style.top = "16px";
    toast.style.right = "16px";
    toast.style.zIndex = "2147483647";
    toast.style.maxWidth = "280px";
    toast.style.padding = "10px 12px";
    toast.style.borderRadius = "8px";
    toast.style.background = "#111827";
    toast.style.color = "#f9fafb";
    toast.style.boxShadow = "0 10px 25px rgba(0, 0, 0, 0.35)";
    toast.style.pointerEvents = "none";
    toast.style.userSelect = "none";
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  }

  function reportBlocked(reason, detail) {
    browser.runtime.sendMessage({ type: "blockPopup", reason, detail }).catch(() => {});
  }

  function handleRuntimeMessage(message) {
    if (!message || !message.type) {
      return;
    }

    if (message.type === "showToast") {
      showToast(message.message || "MyShield blocked something");
    }
  }

  function stripBlankTargets() {
    document.querySelectorAll("a[target='_blank'], a[target='_new'], a[target='_newtab']").forEach((link) => {
      link.removeAttribute("target");
    });
  }

  function removeOverlayAds() {
    if (!strictModeActive) {
      return;
    }

    const elements = Array.from(document.querySelectorAll("*"));
    const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
    const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
    const viewportArea = viewportWidth * viewportHeight;

    for (const element of elements) {
      const style = window.getComputedStyle(element);
      const position = style.position;
      const zIndex = Number.parseInt(style.zIndex || "0", 10);
      if (!["fixed", "absolute"].includes(position) || zIndex <= 1000) {
        continue;
      }

      const rect = element.getBoundingClientRect();
      const area = rect.width * rect.height;
      const coverage = viewportArea > 0 ? area / viewportArea : 0;
      const transparent = Number.parseFloat(style.opacity || "1") < 0.2;
      const hasCrossDomainLink = Array.from(element.querySelectorAll("a")).some((link) => {
        const href = link.getAttribute("href") || "";
        return href && !isSameSite(href);
      });

      if (coverage > 0.3 && (transparent || hasCrossDomainLink)) {
        console.log("MyShield removed overlay", { width: rect.width, height: rect.height, zIndex, coverage });
        element.remove();
      }
    }
  }

  function handleClick(event) {
    if (!strictModeActive) {
      lastUserInteraction = Date.now();
      return;
    }

    lastUserInteraction = Date.now();

    if (event.target && typeof event.target.closest === "function") {
      const clickedLink = event.target.closest("a");
      if (clickedLink) {
        const href = clickedLink.getAttribute("href") || "";
        const target = clickedLink.getAttribute("target") || "";
        if (isDangerousNavigation(href)) {
          event.preventDefault();
          event.stopPropagation();
          showToast("MyShield blocked a risky navigation");
          reportBlocked("popup");
          browser.runtime.sendMessage({ type: "recordStrictModeEvent", category: "adRedirects" }).catch(() => {});
          return;
        }

        if (target === "_blank" || target === "_new") {
          event.preventDefault();
          event.stopPropagation();
          if (href && isSameSite(href)) {
            window.location.assign(href);
          } else {
            showToast("MyShield blocked a cross-site link");
            reportBlocked("popup");
            browser.runtime.sendMessage({ type: "recordStrictModeEvent", category: "adRedirects" }).catch(() => {});
          }
          return;
        }

        if (href && !isSameSite(href) && /^https?:/i.test(href)) {
          event.preventDefault();
          event.stopPropagation();
          showToast(`MyShield blocked ad redirect to ${extractHostname(href)}`);
          reportBlocked("popup");
          browser.runtime.sendMessage({ type: "recordStrictModeEvent", category: "adRedirects" }).catch(() => {});
        }
      }
    }

    if (event.target && typeof event.target.closest === "function") {
      const clickedLink = event.target.closest("a");
      if (!clickedLink) {
        lastMouseDown = Date.now();
        browser.runtime.sendMessage({ type: "markNonLinkClick" }).catch(() => {});
      }
    }
  }

  const originalOpen = window.open.bind(window);
  const safeOpen = function () {
    if (strictModeActive) {
      reportBlocked("popup");
      browser.runtime.sendMessage({ type: "recordStrictModeEvent", category: "popups" }).catch(() => {});
      return null;
    }

    return originalOpen.apply(window, arguments);
  };

  function installStrictModeHandlers() {
    browser.runtime.onMessage.addListener(handleRuntimeMessage);
    document.addEventListener("click", handleClick, true);
    document.addEventListener("mousedown", () => {
      lastMouseDown = Date.now();
      if (strictModeActive) {
        browser.runtime.sendMessage({ type: "markNonLinkClick" }).catch(() => {});
      }
    }, true);
    document.addEventListener("mouseup", () => {
      if (strictModeActive) {
        browser.runtime.sendMessage({ type: "markNonLinkClick" }).catch(() => {});
      }
    }, true);

    Object.defineProperty(window, "open", {
      configurable: false,
      writable: false,
      value: safeOpen
    });

    observer = new MutationObserver(() => {
      stripBlankTargets();
      removeOverlayAds();
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    stripBlankTargets();
    removeOverlayAds();
  }

  async function syncStrictModeState() {
    try {
      const hostname = window.location.hostname || "";
      currentBaseDomain = getBaseDomain(hostname);
      const response = await browser.runtime.sendMessage({ type: "getStrictModeState", domain: normalizeDomain(hostname) });
      strictModeActive = Boolean(response && response.strictMode);
      if (strictModeActive) {
        browser.runtime.sendMessage({ type: "setStrictModeState", domain: normalizeDomain(hostname), value: true }).catch(() => {});
        installStrictModeHandlers();
      }
    } catch (error) {
      console.warn("MyShield: strict mode sync failed", error);
    }
  }

  syncStrictModeState().catch(() => {});
})();
