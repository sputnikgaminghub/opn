/* Opinion (OPN) Theme Manager
   - Persists selected theme in localStorage key: aproTheme
   - Applies CSS custom properties to :root for both the main app and SEO pages
*/
(function () {
  const STORAGE_KEY = "aproTheme";

  const THEME_ORDER = ["default_purple", "cyber_blue_cyan", "magenta_violet", "teal_emerald", "amber_gold", "red_neon", "mono_neon"];

  const THEMES = {
  "default_purple": {
    "--primary": "#00ff88",
    "--primary-dark": "#00cc6a",
    "--secondary": "#667eea",
    "--accent": "#7c3aed",
    "--background": "#0a0b2d",
    "--card-bg": "rgba(255, 255, 255, 0.05)",
    "--text-primary": "#ffffff",
    "--text-secondary": "#a0a0c0",
    "--success": "#00ff88",
    "--warning": "#ffaa00",
    "--error": "#ff4757",
    "--mobile-nav-height": "60px",
    "--web3-primary": "#6c63ff",
    "--web3-success": "#00b09b",
    "--eth-color": "#627eea",
    "--bnb-color": "#f0b90b",
    "--usdt-color": "#26a17b",
    "--bg": "#0b0f14",
    "--card": "#121826",
    "--text": "#e6edf3",
    "--muted": "#9aa7b2",
    "--line": "#233044"
  },
  "cyber_blue_cyan": {
    "--primary": "#00e5ff",
    "--primary-dark": "#00b8cc",
    "--secondary": "#3b82f6",
    "--accent": "#00e5ff",
    "--background": "#0b1020",
    "--card-bg": "rgba(255, 255, 255, 0.05)",
    "--text-primary": "#ffffff",
    "--text-secondary": "#94a3b8",
    "--success": "#00e5ff",
    "--warning": "#f59e0b",
    "--error": "#ef4444",
    "--mobile-nav-height": "60px",
    "--web3-primary": "#3b82f6",
    "--web3-success": "#22c55e",
    "--eth-color": "#627eea",
    "--bnb-color": "#f0b90b",
    "--usdt-color": "#26a17b",
    "--bg": "#0b1020",
    "--card": "#141a2f",
    "--text": "#e6edf3",
    "--muted": "#94a3b8",
    "--line": "#141a2f"
  },
  "magenta_violet": {
    "--primary": "#ff4ecd",
    "--primary-dark": "#e63ab9",
    "--secondary": "#8b5cf6",
    "--accent": "#ff4ecd",
    "--background": "#0a0215",
    "--card-bg": "rgba(255, 255, 255, 0.05)",
    "--text-primary": "#ffffff",
    "--text-secondary": "#a1a1aa",
    "--success": "#ff4ecd",
    "--warning": "#f59e0b",
    "--error": "#ef4444",
    "--mobile-nav-height": "60px",
    "--web3-primary": "#8b5cf6",
    "--web3-success": "#22c55e",
    "--eth-color": "#627eea",
    "--bnb-color": "#f0b90b",
    "--usdt-color": "#26a17b",
    "--bg": "#0a0215",
    "--card": "#16052b",
    "--text": "#e6edf3",
    "--muted": "#a1a1aa",
    "--line": "#16052b"
  },
  "teal_emerald": {
    "--primary": "#2dd4bf",
    "--primary-dark": "#14b8a6",
    "--secondary": "#10b981",
    "--accent": "#2dd4bf",
    "--background": "#071a18",
    "--card-bg": "rgba(255, 255, 255, 0.05)",
    "--text-primary": "#ffffff",
    "--text-secondary": "#9ca3af",
    "--success": "#2dd4bf",
    "--warning": "#f59e0b",
    "--error": "#ef4444",
    "--mobile-nav-height": "60px",
    "--web3-primary": "#10b981",
    "--web3-success": "#2dd4bf",
    "--eth-color": "#627eea",
    "--bnb-color": "#f0b90b",
    "--usdt-color": "#26a17b",
    "--bg": "#071a18",
    "--card": "#0f2a28",
    "--text": "#e6edf3",
    "--muted": "#9ca3af",
    "--line": "#0f2a28"
  },
  "amber_gold": {
    "--primary": "#f5c542",
    "--primary-dark": "#d9a62b",
    "--secondary": "#d97706",
    "--accent": "#f5c542",
    "--background": "#0b0b0b",
    "--card-bg": "rgba(255, 255, 255, 0.05)",
    "--text-primary": "#ffffff",
    "--text-secondary": "#9ca3af",
    "--success": "#f5c542",
    "--warning": "#f59e0b",
    "--error": "#ef4444",
    "--mobile-nav-height": "60px",
    "--web3-primary": "#f5c542",
    "--web3-success": "#22c55e",
    "--eth-color": "#627eea",
    "--bnb-color": "#f0b90b",
    "--usdt-color": "#26a17b",
    "--bg": "#0b0b0b",
    "--card": "#161616",
    "--text": "#e6edf3",
    "--muted": "#9ca3af",
    "--line": "#161616"
  },
  "red_neon": {
    "--primary": "#ff3b3b",
    "--primary-dark": "#e02d2d",
    "--secondary": "#fb7185",
    "--accent": "#ff3b3b",
    "--background": "#0a0f14",
    "--card-bg": "rgba(255, 255, 255, 0.05)",
    "--text-primary": "#ffffff",
    "--text-secondary": "#94a3b8",
    "--success": "#ff3b3b",
    "--warning": "#f59e0b",
    "--error": "#ef4444",
    "--mobile-nav-height": "60px",
    "--web3-primary": "#f43f5e",
    "--web3-success": "#22c55e",
    "--eth-color": "#627eea",
    "--bnb-color": "#f0b90b",
    "--usdt-color": "#26a17b",
    "--bg": "#0a0f14",
    "--card": "#121821",
    "--text": "#e6edf3",
    "--muted": "#94a3b8",
    "--line": "#121821"
  },
  "mono_neon": {
    "--primary": "#00ff88",
    "--primary-dark": "#00cc6a",
    "--secondary": "#a3a3a3",
    "--accent": "#00ff88",
    "--background": "#0d0d0d",
    "--card-bg": "rgba(255, 255, 255, 0.05)",
    "--text-primary": "#ffffff",
    "--text-secondary": "#a3a3a3",
    "--success": "#00ff88",
    "--warning": "#f59e0b",
    "--error": "#ef4444",
    "--mobile-nav-height": "60px",
    "--web3-primary": "#00ff88",
    "--web3-success": "#00ff88",
    "--eth-color": "#627eea",
    "--bnb-color": "#f0b90b",
    "--usdt-color": "#26a17b",
    "--bg": "#0d0d0d",
    "--card": "#1a1a1a",
    "--text": "#e6edf3",
    "--muted": "#a3a3a3",
    "--line": "#1a1a1a"
  }
};

  function safeGetThemeId() {
    try { return localStorage.getItem(STORAGE_KEY) || ""; } catch (e) { return ""; }
  }

  function safeSetThemeId(id) {
    try { localStorage.setItem(STORAGE_KEY, id); } catch (e) {}
  }

  function applyTheme(themeId) {
    const id = (themeId && THEMES[themeId]) ? themeId : THEME_ORDER[0];
    const vars = THEMES[id] || {};
    const root = document.documentElement;

    Object.entries(vars).forEach(([k, v]) => {
      if (k && typeof v === "string") root.style.setProperty(k, v);
    });

    root.setAttribute("data-theme", id);
    safeSetThemeId(id);

    // Update any UI labels if present
    const badge = document.getElementById("currentTheme");
    if (badge) badge.textContent = id.replace(/_/g, " ").toUpperCase();
    const active = document.querySelectorAll("[data-theme-option]");
    active.forEach((el) => {
      el.classList.toggle("active", el.getAttribute("data-theme-option") === id);
    });

    return id;
  }

  function getThemes() {
    return THEME_ORDER.map((id) => ({ id, name: ({"default_purple": "Default Purple", "cyber_blue_cyan": "Cyber Blue/Cyan", "magenta_violet": "Magenta/Violet", "teal_emerald": "Teal/Emerald", "amber_gold": "Amber/Gold", "red_neon": "Red Neon", "mono_neon": "Mono Neon"})[id] || id }));
  }

  // Apply saved theme immediately
  const initial = applyTheme(safeGetThemeId());

  // Expose API for templates
  window.APROTheme = {
    THEMES,
    THEME_ORDER,
    getThemes,
    applyTheme,
    getCurrent: () => (document.documentElement.getAttribute("data-theme") || initial)
  };
})();