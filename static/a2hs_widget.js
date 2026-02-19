(function(){
  const LS = {
    viewerKey: "opn_a2hs_viewer_key",
    totalActive: "opn_a2hs_total_active_s",
    sessionActive: "opn_a2hs_session_active_s",
    lastVisitAt: "opn_a2hs_last_visit_at",
    visitCount: "opn_a2hs_visits",
    actionCount: "opn_a2hs_actions",
    dismissedUntil: "opn_a2hs_dismissed_until",
    lastPromptAt: "opn_a2hs_last_prompt_at"
  };

  const THRESH = {
    totalActiveS: 180,   // 3 minutes accumulated
    sessionActiveS: 60,  // at least 1 minute in a single session
    visits: 3,
    actions: 2
  };

  const SNOOZE = {
    notNowMs: 7 * 24 * 60 * 60 * 1000,
    closeMs: 24 * 60 * 60 * 1000
  };

  // ---------- helpers ----------
  function nowMs(){ return Date.now(); }
  function getInt(k, def=0){
    const v = parseInt(localStorage.getItem(k) || "", 10);
    return Number.isFinite(v) ? v : def;
  }
  function setInt(k, v){ localStorage.setItem(k, String(v)); }
  function getStr(k, def=""){ return localStorage.getItem(k) || def; }
  function setStr(k, v){ localStorage.setItem(k, v); }

  function isStandalone(){
    const mq = window.matchMedia && window.matchMedia("(display-mode: standalone)").matches;
    const iosStandalone = window.navigator && window.navigator.standalone === true;
    return !!(mq || iosStandalone);
  }

  function isIOS(){
    const ua = navigator.userAgent || "";
    const iOS = /iPad|iPhone|iPod/.test(ua);
    const isMS = navigator.maxTouchPoints && navigator.maxTouchPoints > 1 && /Macintosh/.test(ua); // iPadOS
    return iOS || isMS;
  }

  function isAndroidChrome(){
    const ua = navigator.userAgent || "";
    const isAndroid = /Android/i.test(ua);
    const isChrome = /Chrome\//i.test(ua) && !/Edg\//i.test(ua) && !/OPR\//i.test(ua) && !/SamsungBrowser\//i.test(ua);
    return isAndroid && isChrome;
  }

  function ensureViewerKey(){
    let k = getStr(LS.viewerKey);
    if(!k){
      k = (crypto && crypto.randomUUID) ? crypto.randomUUID() : String(nowMs()) + "_" + Math.random().toString(16).slice(2);
      setStr(LS.viewerKey, k);
    }
    return k;
  }

  // ---------- visit/session tracking ----------
  function bumpVisit(){
    const last = getInt(LS.lastVisitAt, 0);
    const gapMs = 30 * 60 * 1000; // count a new visit if >30 min since last page load
    if(!last || (nowMs() - last) > gapMs){
      const vc = getInt(LS.visitCount, 0) + 1;
      setInt(LS.visitCount, vc);
    }
    setInt(LS.lastVisitAt, nowMs());
  }

  // ---------- active time tracking ----------
  let lastInteractionMs = nowMs();
  let heartbeat = null;

  function markInteraction(){
    lastInteractionMs = nowMs();
  }

  function startHeartbeat(){
    if(heartbeat) return;
    heartbeat = setInterval(() => {
      if(document.visibilityState !== "visible") return;
      const idleMs = nowMs() - lastInteractionMs;
      if(idleMs > 15000) return; // only count if interacted in last 15s

      // add 5 seconds active time
      setInt(LS.totalActive, getInt(LS.totalActive, 0) + 5);
      setInt(LS.sessionActive, getInt(LS.sessionActive, 0) + 5);

      maybeShowPrompt();
    }, 5000);
  }

  function resetSessionCounterOnNewTabOpen(){
    // If last visit was long ago, reset session active to 0
    const last = getInt(LS.lastVisitAt, 0);
    if(!last || (nowMs() - last) > (30 * 60 * 1000)){
      setInt(LS.sessionActive, 0);
    }
  }

  // ---------- action tracking ----------
  function bumpAction(){
    const ac = getInt(LS.actionCount, 0) + 1;
    setInt(LS.actionCount, ac);
    maybeShowPrompt();
  }

  function hookActions(){
    // Count meaningful interactions: clicks/taps on buttons/links excluding the prompt itself.
    document.addEventListener("click", (e) => {
      markInteraction();
      const target = e.target && e.target.closest ? e.target.closest("a,button,[role='button']") : null;
      if(!target) return;

      // ignore inside A2HS UI
      if(target.closest && target.closest("#a2hs-sheet")) return;

      // ignore if hidden/disabled
      if(target.disabled) return;

      // heuristic: if it's a navigation or primary CTA, count
      const tag = target.tagName.toLowerCase();
      const hasHref = tag === "a" && target.getAttribute("href");
      const isButton = tag === "button";
      const roleBtn = target.getAttribute("role") === "button";

      if(hasHref || isButton || roleBtn){
        bumpAction();
      }
    }, { passive: true });

    document.addEventListener("touchstart", markInteraction, { passive: true });
    document.addEventListener("scroll", markInteraction, { passive: true });
    document.addEventListener("keydown", markInteraction, { passive: true });

    // If announcements widget exists, count opening the drawer as an action (strong signal)
    const bell = document.getElementById("announce-bell");
    if(bell){
      bell.addEventListener("click", () => bumpAction(), { passive: true });
    }
  }

  // ---------- Android install prompt ----------
  let deferredPrompt = null;
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredPrompt = e;
  });

  window.addEventListener("appinstalled", () => {
    // once installed, never prompt again
    setInt(LS.dismissedUntil, nowMs() + (3650 * 24 * 60 * 60 * 1000)); // 10 years
  });

  // ---------- UI ----------
  function getEls(){
    return {
      overlay: document.getElementById("a2hs-overlay"),
      sheet: document.getElementById("a2hs-sheet"),
      close: document.getElementById("a2hs-close"),
      add: document.getElementById("a2hs-add"),
      notnow: document.getElementById("a2hs-notnow"),
      androidBox: document.getElementById("a2hs-android-instructions"),
      androidOk: document.getElementById("a2hs-android-ok"),
      iosBox: document.getElementById("a2hs-ios-instructions"),
      iosOk: document.getElementById("a2hs-ios-ok")
    };
  }

  function showOverlay(){
    const els = getEls();
    if(!els.overlay) return;
    els.overlay.classList.remove("a2hs-hidden");
    els.overlay.setAttribute("aria-hidden", "false");
    setInt(LS.lastPromptAt, nowMs());
  }

  function hideOverlay(snoozeMs){
    const els = getEls();
    if(!els.overlay) return;
    els.overlay.classList.add("a2hs-hidden");
    els.overlay.setAttribute("aria-hidden", "true");

    if(snoozeMs){
      setInt(LS.dismissedUntil, nowMs() + snoozeMs);
    }
  }

  function showIOSInstructions(){
    const els = getEls();
    if(!els.iosBox) return;
    els.iosBox.classList.remove("a2hs-hidden");
    // hide main buttons to avoid confusion
    els.add.classList.add("a2hs-hidden");
    els.notnow.classList.add("a2hs-hidden");
  }

  function showAndroidInstructions(){
    const els = getEls();
    if(!els.androidBox) return;
    els.androidBox.classList.remove("a2hs-hidden");
    // hide main buttons to avoid confusion
    els.add.classList.add("a2hs-hidden");
    els.notnow.classList.add("a2hs-hidden");
  }

  function resetMainButtons(){
    const els = getEls();
    if(els.iosBox) els.iosBox.classList.add("a2hs-hidden");
    if(els.androidBox) els.androidBox.classList.add("a2hs-hidden");
    els.add.classList.remove("a2hs-hidden");
    els.notnow.classList.remove("a2hs-hidden");
  }

  async function handleAdd(){
    // Android native prompt if available
    if(deferredPrompt){
      deferredPrompt.prompt();
      try{
        await deferredPrompt.userChoice;
      }catch(_){}
      deferredPrompt = null;
      hideOverlay(SNOOZE.notNowMs);
      return;
    }

    // iOS: show instructions
    if(isIOS() && !isStandalone()){
      showIOSInstructions();
      return;
    }

    // Android Chrome but prompt not yet available (installability heuristics not satisfied or prompt not fired yet)
    if(isAndroidChrome() && !isStandalone()){
      showAndroidInstructions();
      return;
    }

    // Other browsers: just snooze (no native support)
    hideOverlay(SNOOZE.notNowMs);
  }

  function wireUI(){
    const els = getEls();
    if(!els.overlay) return;

    els.close && els.close.addEventListener("click", () => {
      resetMainButtons();
      hideOverlay(SNOOZE.closeMs);
    });

    els.notnow && els.notnow.addEventListener("click", () => {
      resetMainButtons();
      hideOverlay(SNOOZE.notNowMs);
    });

    els.add && els.add.addEventListener("click", handleAdd);

    els.overlay.addEventListener("click", (e) => {
      if(e.target === els.overlay){
        resetMainButtons();
        hideOverlay(SNOOZE.closeMs);
      }
    });

    els.iosOk && els.iosOk.addEventListener("click", () => {
      resetMainButtons();
      hideOverlay(SNOOZE.notNowMs);
    });

    els.androidOk && els.androidOk.addEventListener("click", () => {
      resetMainButtons();
      hideOverlay(SNOOZE.notNowMs);
    });
  }

  // ---------- eligibility ----------
  function eligible(){
    if(isStandalone()) return false;

    const dismissedUntil = getInt(LS.dismissedUntil, 0);
    if(dismissedUntil && nowMs() < dismissedUntil) return false;

    const total = getInt(LS.totalActive, 0);
    const session = getInt(LS.sessionActive, 0);
    const visits = getInt(LS.visitCount, 0);
    const actions = getInt(LS.actionCount, 0);

    if(total < THRESH.totalActiveS) return false;
    if(session < THRESH.sessionActiveS) return false;
    if(visits < THRESH.visits) return false;
    if(actions < THRESH.actions) return false;

    // On Android, if we never received beforeinstallprompt, we can still show (manual-ish) — but keep it modest
    return true;
  }

  let alreadyShownThisPage = false;
  function maybeShowPrompt(){
    if(alreadyShownThisPage) return;
    const els = getEls();
    if(!els.overlay) return;

    if(eligible()){
      alreadyShownThisPage = true;
      showOverlay();
    }
  }

  // ---------- init ----------
  function init(){
    // Register service worker early so the app can satisfy PWA installability requirements.
    // Safe to call on pages that already register it; browser will treat it as a no-op update check.
    if("serviceWorker" in navigator){
      navigator.serviceWorker.register("/static/sw.js").catch(() => {});
    }

    ensureViewerKey();
    resetSessionCounterOnNewTabOpen();
    bumpVisit();
    wireUI();
    hookActions();
    startHeartbeat();

    // attempt soon after load if thresholds already met
    setTimeout(maybeShowPrompt, 1500);
  }

  if(document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", init);
  }else{
    init();
  }
})();
