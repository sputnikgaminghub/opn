// Command Center Theme (Theme 1)
// Adds: top HUD + command palette (Ctrl/Cmd+K)
// Does NOT change backend/API; hooks into existing global functions where possible.

(function(){
  function fmt(n){
    const num = Number(n || 0);
    // reuse existing formatter if present
    if (typeof window.formatNumber === 'function') return window.formatNumber(Math.floor(num));
    return Math.floor(num).toLocaleString();
  }

  function ensureTopbar(){
    if (document.getElementById('ccTopbar')) return;
    const bar = document.createElement('div');
    bar.id = 'ccTopbar';
    bar.innerHTML = `
      <div class="cc-title">
        <strong>Command Center</strong>
        <span id="ccSub">Press <b>⌘K</b> / <b>Ctrl+K</b> for actions</span>
      </div>
      <div class="cc-hud" id="ccHud">
        <div class="cc-pill"><span class="k">Wallet</span><span class="v" id="ccWallet">Not connected</span></div>
        <div class="cc-pill primary"><span class="k">Total</span><span class="v" id="ccTotal">—</span></div>
        <div class="cc-pill"><span class="k">Available</span><span class="v" id="ccAvail">—</span></div>
      </div>
    `;
    document.body.appendChild(bar);
  }

  function setHudWallet(addr){
    const el = document.getElementById('ccWallet');
    if (!el) return;
    if (!addr){
      el.textContent = 'Not connected';
      return;
    }
    const short = addr.slice(0, 6) + '…' + addr.slice(-4);
    el.textContent = short;
    el.title = addr;
  }

  function updateHudFromBalances(bal){
    ensureTopbar();
    const total = (bal && (bal.total_balance ?? bal.total_earned ?? bal.total)) ?? null;
    const avail = (bal && (bal.available_for_withdrawal ?? bal.withdrawable ?? bal.available)) ?? null;

    const totalEl = document.getElementById('ccTotal');
    const availEl = document.getElementById('ccAvail');
    if (totalEl && total !== null) totalEl.textContent = `${fmt(total)} OPN`;
    if (availEl && avail !== null) availEl.textContent = `${fmt(avail)} OPN`;

    // Add/refresh detail pills (welcome/referrals/achievements/tasks/claim window)
    const hud = document.getElementById('ccHud');
    if (!hud || !bal) return;

    // Remove old detail pills
    [...hud.querySelectorAll('[data-cc-detail]')].forEach(n => n.remove());

    const details = [
      {k:'Welcome', v: bal.welcome_bonus},
      {k:'Referrals', v: bal.referral_earnings},
      {k:'Achievements', v: bal.achievement_earnings},
      {k:'Tasks', v: bal.task_earnings},
      {k:'Claim Win', v: bal.claim_window_earnings},
    ];

    // insert after wallet pill
    const walletPill = hud.querySelector('.cc-pill');
    details.forEach(d => {
      const pill = document.createElement('div');
      pill.className = 'cc-pill';
      pill.dataset.ccDetail = '1';
      pill.innerHTML = `<span class="k">${d.k}</span><span class="v">${fmt(d.v)} OPN</span>`;
      hud.insertBefore(pill, walletPill.nextSibling);
    });
  }

  function getActiveWallet(){
    // existing helpers in template:
    if (typeof window.getDashboardWalletAddress === 'function') {
      const w = window.getDashboardWalletAddress();
      if (w) return w;
    }
    const input = document.getElementById('airdropWalletAddress');
    if (input && input.value && input.value.trim().startsWith('0x')) return input.value.trim();
    return null;
  }

  // ---- Command Palette ----
  const ACTIONS = [
    {id:'presale', icon:'fa-fire', title:'Presale', subtitle:'Buy OPN / record transactions'},
    {id:'tokenomics', icon:'fa-chart-pie', title:'Tokenomics', subtitle:'Supply, allocations, pricing'},
    {id:'roadmap', icon:'fa-map', title:'Roadmap', subtitle:'Milestones & delivery'},
    {id:'partners', icon:'fa-handshake', title:'Partners', subtitle:'Integrations & backers'},
    {id:'team', icon:'fa-users', title:'Team', subtitle:'Core contributors'},
    {id:'airdrop', icon:'fa-gift', title:'Airdrop', subtitle:'Eligibility, claim, referrals'},
    {href:'/stake', icon:'fa-coins', title:'Stake', subtitle:'Staking dashboard (external)'},
  ];

  function ensurePalette(){
    if (document.getElementById('ccPaletteBackdrop')) return;
    const back = document.createElement('div');
    back.id = 'ccPaletteBackdrop';
    back.innerHTML = `
      <div id="ccPalette" role="dialog" aria-modal="true" aria-label="Command Palette">
        <div id="ccPaletteHeader">
          <i class="fas fa-magnifying-glass" style="color:#1d4ed8"></i>
          <input id="ccPaletteInput" placeholder="Type to search… (e.g., airdrop, stake, roadmap)" autocomplete="off" />
          <div class="hint">Esc to close</div>
        </div>
        <div id="ccPaletteList"></div>
      </div>
    `;
    back.addEventListener('click', (e)=>{
      if (e.target === back) closePalette();
    });
    document.body.appendChild(back);

    renderPaletteList('');
    const input = document.getElementById('ccPaletteInput');
    input.addEventListener('input', ()=>renderPaletteList(input.value));
    input.addEventListener('keydown', (e)=>{
      if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
      if (e.key === 'Enter') {
        const first = document.querySelector('#ccPaletteList .ccPalItem');
        if (first) first.click();
      }
    });
  }

  function renderPaletteList(q){
    const list = document.getElementById('ccPaletteList');
    if (!list) return;
    const query = (q||'').trim().toLowerCase();
    const items = ACTIONS.filter(a => {
      const t = (a.title||'').toLowerCase();
      const s = (a.subtitle||'').toLowerCase();
      const id = (a.id||'').toLowerCase();
      return !query || t.includes(query) || s.includes(query) || id.includes(query);
    });

    list.innerHTML = items.map(a => `
      <div class="ccPalItem" data-id="${a.id||''}" data-href="${a.href||''}">
        <div class="icon"><i class="fas ${a.icon}"></i></div>
        <div class="text">
          <strong>${a.title}</strong>
          <span>${a.subtitle}</span>
        </div>
      </div>
    `).join('');

    [...list.querySelectorAll('.ccPalItem')].forEach(el=>{
      el.addEventListener('click', ()=>{
        const href = el.getAttribute('data-href');
        const id = el.getAttribute('data-id');
        closePalette();
        if (href) {
          window.location.href = href;
          return;
        }
        if (id && typeof window.navigateToSection === 'function') {
          window.navigateToSection(id);
        } else if (id) {
          // fallback: emulate click on existing nav link
          const link = document.querySelector(`.nav-link[data-section="${id}"]`);
          if (link) link.click();
        }
      });
    });
  }

  function openPalette(){
    ensurePalette();
    const back = document.getElementById('ccPaletteBackdrop');
    back.classList.add('open');
    const input = document.getElementById('ccPaletteInput');
    input.value = '';
    renderPaletteList('');
    input.focus();
  }

  function closePalette(){
    const back = document.getElementById('ccPaletteBackdrop');
    if (back) back.classList.remove('open');
  }

  function initPaletteHotkeys(){
    window.addEventListener('keydown', (e)=>{
      const isMac = navigator.platform.toLowerCase().includes('mac');
      const cmdk = isMac && e.metaKey && e.key.toLowerCase() === 'k';
      const ctrlk = !isMac && e.ctrlKey && e.key.toLowerCase() === 'k';
      if (cmdk || ctrlk){
        e.preventDefault();
        openPalette();
      }
      if (e.key === 'Escape'){
        closePalette();
      }
    });
  }

  function hookBalanceRenderers(){
    // Hook withdrawal balances renderer (most reliable aggregate of all buckets)
    if (typeof window.renderWithdrawalBalances === 'function' && !window.__cc_wrapped_withdrawal_balances){
      const original = window.renderWithdrawalBalances;
      window.renderWithdrawalBalances = function(bal){
        try{ original(bal); } finally { updateHudFromBalances(bal); }
      };
      window.__cc_wrapped_withdrawal_balances = true;
    }

    // Hook airdrop eligibility check if present
    if (typeof window.checkAirdropEligibility === 'function' && !window.__cc_wrapped_check){
      const orig = window.checkAirdropEligibility;
      window.checkAirdropEligibility = async function(){
        const res = await orig.apply(this, arguments);
        setHudWallet(getActiveWallet());
        return res;
      };
      window.__cc_wrapped_check = true;
    }

    // Fallback: observe wallet dashboard updates and try to infer numbers
    const target = document.getElementById('airdropDashboard');
    if (target){
      const obs = new MutationObserver(()=>{
        setHudWallet(getActiveWallet());
      });
      obs.observe(target, {subtree:true, childList:true});
    }
  }

  document.addEventListener('DOMContentLoaded', ()=>{
    ensureTopbar();
    setHudWallet(getActiveWallet());
    initPaletteHotkeys();
    hookBalanceRenderers();

    // Add a subtle hint in the sidebar logo area (non-invasive)
    const logo = document.querySelector('.nav-logo');
    if (logo && !logo.querySelector('.ccHint')){
      const hint = document.createElement('div');
      hint.className = 'ccHint';
      hint.style.cssText = 'margin-left:auto;display:flex;gap:8px;align-items:center;color:rgba(232,238,252,0.75);font-size:12px;font-weight:800;';
      hint.innerHTML = '<i class="fas fa-keyboard"></i><span>⌘K</span>';
      logo.appendChild(hint);
    }
  });
})();