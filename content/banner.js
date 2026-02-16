/**
 * ScAIm Banner — Warning overlay injected at the top of suspicious pages.
 */
const ScaimBanner = {
  _bannerId: "scaim-banner",
  _dismissedUrls: new Set(),
  _removeTimer: null,

  /**
   * Show the warning banner for the given assessment.
   * @param {{ level: string, score: number, summary: string, findings: Array }} assessment
   */
  show(assessment) {
    // Check if dismissed for this page this session (in-memory only —
    // sessionStorage is shared with host page and can be exploited to suppress banners)
    if (this._dismissedUrls.has(window.location.href)) return;

    // Cancel any pending remove timer (prevents stale dismiss/trust setTimeout
    // from removing a newly-shown banner during the 400ms fade-out window)
    clearTimeout(this._removeTimer);

    // Remove existing banner if any
    this.remove();

    const banner = this._createBanner(assessment);

    document.body.prepend(banner);

    // Trigger slide-in animation
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        banner.classList.add("scaim-visible");
      });
    });
  },

  /**
   * Show a compact lite banner that auto-hides after 5 seconds.
   */
  showLite(assessment) {
    if (this._dismissedUrls.has(window.location.href)) return;
    clearTimeout(this._removeTimer);
    this.remove();

    const levelConfig = this._getLevelConfig(assessment.level);
    const banner = document.createElement("div");
    banner.id = this._bannerId;
    banner.className = `scaim-banner-lite scaim-${assessment.level}`;

    const content = document.createElement("div");
    content.className = "scaim-lite-content";

    const icon = document.createElement("span");
    icon.className = "scaim-lite-icon";
    icon.textContent = levelConfig.icon;

    const text = document.createElement("span");
    text.className = "scaim-lite-text";
    text.textContent = levelConfig.title + " \u2014 Score: " + assessment.score + "/100";

    const dismissBtn = document.createElement("button");
    dismissBtn.className = "scaim-lite-dismiss";
    dismissBtn.title = "Dismiss";
    dismissBtn.textContent = "\u00D7";

    content.appendChild(icon);
    content.appendChild(text);
    content.appendChild(dismissBtn);
    banner.appendChild(content);
    dismissBtn.addEventListener("click", () => {
      clearTimeout(this._removeTimer);
      banner.classList.remove("scaim-visible");
      this._dismissedUrls.add(window.location.href);
      this._removeTimer = setTimeout(() => this.remove(), 400);
    });

    document.body.prepend(banner);

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        banner.classList.add("scaim-visible");
      });
    });

    // Auto-hide after 5 seconds
    this._removeTimer = setTimeout(() => {
      if (document.getElementById(this._bannerId)) {
        banner.classList.remove("scaim-visible");
        this._removeTimer = setTimeout(() => this.remove(), 400);
      }
    }, 5000);
  },

  /**
   * Remove the banner and spacer from the DOM.
   */
  remove() {
    const existing = document.getElementById(this._bannerId);
    if (existing) existing.remove();
  },

  /**
   * Create the banner DOM element.
   */
  _createBanner(assessment) {
    const banner = document.createElement("div");
    banner.id = this._bannerId;
    banner.className = "scaim-" + assessment.level;

    const levelConfig = this._getLevelConfig(assessment.level);
    const topFindings = assessment.findings.slice(0, 3);
    const VALID_SEV = ["critical", "high", "medium", "low"];

    // Build DOM structure
    const content = document.createElement("div");
    content.className = "scaim-banner-content";

    // Header row
    const header = document.createElement("div");
    header.className = "scaim-banner-header";

    const iconEl = document.createElement("span");
    iconEl.className = "scaim-banner-icon";
    iconEl.textContent = levelConfig.icon;

    const titleEl = document.createElement("span");
    titleEl.className = "scaim-banner-title";
    titleEl.textContent = levelConfig.title;

    const scoreBadge = document.createElement("span");
    scoreBadge.className = "scaim-score-badge";
    scoreBadge.textContent = "Score: " + assessment.score + "/100";

    const summaryEl = document.createElement("span");
    summaryEl.className = "scaim-banner-summary";
    summaryEl.textContent = assessment.summary;

    const actions = document.createElement("div");
    actions.className = "scaim-banner-actions";

    const toggleBtn = document.createElement("button");
    toggleBtn.className = "scaim-banner-btn scaim-btn-details";
    toggleBtn.textContent = "Show all findings (" + assessment.findings.length + ")";

    const trustBtn = document.createElement("button");
    trustBtn.className = "scaim-banner-btn scaim-btn-trust";
    trustBtn.title = "Add this site to your trusted allowlist";
    trustBtn.textContent = "Trust this site";

    const dismissBtn = document.createElement("button");
    dismissBtn.className = "scaim-banner-btn scaim-btn-dismiss";
    dismissBtn.textContent = "Dismiss";

    actions.appendChild(toggleBtn);
    actions.appendChild(trustBtn);
    actions.appendChild(dismissBtn);

    header.appendChild(iconEl);
    header.appendChild(titleEl);
    header.appendChild(scoreBadge);
    header.appendChild(summaryEl);
    header.appendChild(actions);
    content.appendChild(header);

    // Top findings preview
    if (topFindings.length > 0) {
      const topDiv = document.createElement("div");
      topDiv.className = "scaim-top-findings";
      topFindings.forEach(f => {
        const tf = document.createElement("div");
        tf.className = "scaim-top-finding";
        tf.textContent = f.message;
        topDiv.appendChild(tf);
      });
      content.appendChild(topDiv);
    }

    // Full findings panel
    const findingsPanel = document.createElement("div");
    findingsPanel.className = "scaim-banner-findings";

    assessment.findings.forEach(f => {
      const sev = VALID_SEV.includes(f.severity) ? f.severity : "medium";

      const findingDiv = document.createElement("div");
      findingDiv.className = "scaim-finding";

      const sevSpan = document.createElement("span");
      sevSpan.className = "scaim-finding-severity scaim-severity-" + sev;
      sevSpan.textContent = sev;

      const textSpan = document.createElement("span");
      textSpan.className = "scaim-finding-text";

      const catSpan = document.createElement("span");
      catSpan.className = "scaim-finding-category";
      catSpan.textContent = "[" + f.category + "]";

      textSpan.appendChild(catSpan);
      textSpan.appendChild(document.createTextNode(" " + f.message));

      findingDiv.appendChild(sevSpan);
      findingDiv.appendChild(textSpan);
      findingsPanel.appendChild(findingDiv);
    });

    const privacy = document.createElement("div");
    privacy.className = "scaim-privacy";
    privacy.textContent = "All analysis is performed locally in your browser. ScAIm does not collect, transmit, or log any of your personal data.";
    findingsPanel.appendChild(privacy);

    content.appendChild(findingsPanel);
    banner.appendChild(content);

    // Event listeners
    toggleBtn.addEventListener("click", () => {
      const isExpanded = findingsPanel.classList.toggle("scaim-expanded");
      toggleBtn.textContent = isExpanded
        ? "Hide findings"
        : "Show all findings (" + assessment.findings.length + ")";
    });

    trustBtn.addEventListener("click", () => {
      const hostname = window.location.hostname;
      // Update content script's in-memory allowlist directly so rerun() recognizes it
      if (typeof DomainLists !== "undefined") {
        DomainLists.addToAllowlist(hostname);
      }
      // Also persist via background service worker
      try {
        chrome.runtime.sendMessage({
          type: "SCAIM_ALLOWLIST_ADD",
          hostname: hostname
        });
      } catch (e) { /* ignore */ }
      // Remove banner immediately
      banner.classList.remove("scaim-visible");
      ScaimBanner._removeTimer = setTimeout(() => this.remove(), 400);
    });

    dismissBtn.addEventListener("click", () => {
      banner.classList.remove("scaim-visible");

      // Remember dismissal for this page (in-memory, inaccessible to host page)
      ScaimBanner._dismissedUrls.add(window.location.href);

      ScaimBanner._removeTimer = setTimeout(() => this.remove(), 400);
    });

    return banner;
  },

  /**
   * Get configuration for each threat level.
   */
  _getLevelConfig(level) {
    const configs = {
      caution: {
        icon: "\u26A0\uFE0F",
        title: "ScAIm — Caution"
      },
      warning: {
        icon: "\u{1F6A8}",
        title: "ScAIm — Warning"
      },
      danger: {
        icon: "\u{1F6D1}",
        title: "ScAIm — Danger"
      }
    };
    return configs[level] || configs.caution;
  },

};
