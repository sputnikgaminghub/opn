(function(){
  const bell = document.getElementById('apro-announce-bell');
  const badge = document.getElementById('apro-announce-badge');
  const overlay = document.getElementById('apro-announce-overlay');
  const drawer = document.getElementById('apro-announce-drawer');
  const closeBtn = document.getElementById('apro-announce-close');
  const listEl = document.getElementById('apro-announce-list');
  const detailEl = document.getElementById('apro-announce-detail');
  const detailInner = document.getElementById('apro-announce-detail-inner');
  const backBtn = document.getElementById('apro-announce-back');
  const bannerEl = document.getElementById('apro-critical-banner');

  if(!bell || !overlay || !listEl || !detailEl){
    return;
  }

  const VIEWER_KEY_STORAGE = 'apro_viewer_key';
  const wallet = (localStorage.getItem('apro_wallet') || '').trim() || null;
  let viewerKey = (localStorage.getItem(VIEWER_KEY_STORAGE) || '').trim();
  if(!viewerKey){
    viewerKey = (crypto && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now()) + Math.random();
    localStorage.setItem(VIEWER_KEY_STORAGE, viewerKey);
  }

  let announcementsCache = [];

  function fmtDate(iso){
    try{
      const d = new Date(iso);
      return d.toLocaleDateString(undefined, { year:'numeric', month:'short', day:'2-digit' });
    }catch(e){
      return '';
    }
  }

  function openOverlay(){
    overlay.classList.remove('apro-hidden');
    overlay.classList.add('apro-open');
    overlay.setAttribute('aria-hidden','false');
    document.body.style.overflow = 'hidden';
  }

  function closeOverlay(){
    overlay.classList.remove('apro-open');
    overlay.setAttribute('aria-hidden','true');
    document.body.style.overflow = '';
    // allow transition to finish before hiding
    setTimeout(()=>{ overlay.classList.add('apro-hidden'); }, 180);
    showList();
  }

  function showList(){
    detailEl.classList.add('apro-hidden');
    listEl.classList.remove('apro-hidden');
    detailInner.innerHTML = '';
  }

  function showDetail(){
    listEl.classList.add('apro-hidden');
    detailEl.classList.remove('apro-hidden');
  }

  async function api(url, opts={}){
    const res = await fetch(url, {
      credentials: 'same-origin',
      headers: { 'Content-Type':'application/json' },
      ...opts
    });
    const data = await res.json().catch(()=>null);
    if(!res.ok){
      const msg = data && (data.error || data.message) ? (data.error || data.message) : `Request failed (${res.status})`;
      throw new Error(msg);
    }
    return data;
  }

  function renderList(items){
    listEl.innerHTML = '';
    let unreadCount = 0;

    items.forEach(a=>{
      if(!a.has_viewed){ unreadCount += 1; }
      const el = document.createElement('div');
      el.className = 'apro-announce-item';
      el.setAttribute('data-id', a.id);
      const tag = a.type === 'critical' ? '<span class="apro-tag critical">critical</span>' : '<span class="apro-tag">normal</span>';
      const unread = !a.has_viewed ? '<span class="apro-announce-unread" title="Unread"></span>' : '';
      el.innerHTML = `
        <div class="apro-announce-item-top">
          <div class="apro-announce-item-title">${unread}${escapeHtml(a.title)}</div>
          <div class="apro-announce-item-meta">
            <span>👁 ${Number(a.unique_views||0)}</span>
            <span>${fmtDate(a.created_at)}</span>
          </div>
        </div>
        <div style="margin-top:8px">${tag}</div>
      `;
      el.onclick = ()=> openAnnouncement(a.id);
      listEl.appendChild(el);
    });

    // Unread badge on bell (Option A)
    if(badge){
      if(unreadCount > 0){
        badge.textContent = String(unreadCount);
        badge.style.display = 'block';
      }else{
        badge.textContent = '';
        badge.style.display = 'none';
      }
    }
  }

  function escapeHtml(s){
    return String(s||'')
      .replaceAll('&','&amp;')
      .replaceAll('<','&lt;')
      .replaceAll('>','&gt;')
      .replaceAll('"','&quot;')
      .replaceAll("'",'&#39;');
  }

  async function loadAnnouncements(){
    const q = new URLSearchParams();
    if(wallet) q.set('wallet', wallet);
    if(viewerKey) q.set('viewer_key', viewerKey);

    const data = await api('/api/announcements?' + q.toString());
    announcementsCache = data.announcements || [];
    renderList(announcementsCache);

    // Critical banner
    const cb = data.critical_banner;
    if(cb && cb.id){
      const dismissKey = 'apro_critical_dismissed_' + cb.id;
      const dismissed = localStorage.getItem(dismissKey) === '1';
      if(!dismissed){
        bannerEl.classList.remove('apro-hidden');
        bannerEl.innerHTML = `
          <div><strong>Critical:</strong> ${escapeHtml(cb.title)}</div>
          <div class="apro-critical-actions">
            <button class="apro-critical-btn" id="apro-critical-read" type="button">Read</button>
            <button class="apro-critical-btn" id="apro-critical-dismiss" type="button">✕</button>
          </div>
        `;
        const readBtn = document.getElementById('apro-critical-read');
        const disBtn = document.getElementById('apro-critical-dismiss');
        if(readBtn) readBtn.onclick = ()=> openAnnouncement(cb.id, true);
        if(disBtn) disBtn.onclick = ()=>{
          localStorage.setItem(dismissKey,'1');
          bannerEl.classList.add('apro-hidden');
        };
      }else{
        bannerEl.classList.add('apro-hidden');
      }
    }else{
      bannerEl.classList.add('apro-hidden');
    }
  }

  async function openAnnouncement(id, openFromBanner=false){
    try{
      openOverlay();
      showDetail();
      detailInner.innerHTML = '<div style="padding:10px; color:rgba(185,192,212,1)">Loading…</div>';

      const detail = await api('/api/announcements/' + encodeURIComponent(id));
      detailInner.innerHTML = `
        <div style="display:flex; justify-content:space-between; gap:10px; align-items:flex-start">
          <div>
            <div style="font-weight:900; font-size:16px; margin-bottom:2px">${escapeHtml(detail.title)}</div>
            <div style="font-size:12px; color:rgba(185,192,212,1)">${fmtDate(detail.created_at)} • 👁 <span id="apro-views-${detail.id}">${Number(detail.unique_views||0)}</span></div>
          </div>
          ${detail.type === 'critical' ? '<span class="apro-tag critical">critical</span>' : '<span class="apro-tag">normal</span>'}
        </div>
        <div style="margin-top:12px" class="apro-announce-detail-body">${detail.body_html||''}</div>
      `;

      // Record view (idempotent)
      const v = await api('/api/announcements/' + encodeURIComponent(id) + '/view', {
        method:'POST',
        body: JSON.stringify({ wallet: wallet, viewer_key: viewerKey })
      });
      const viewsEl = document.getElementById(`apro-views-${detail.id}`);
      if(viewsEl && v && typeof v.unique_views !== 'undefined'){
        viewsEl.textContent = String(v.unique_views);
      }

      // Update cache so badge clears immediately
      announcementsCache = announcementsCache.map(a=>{
        if(a.id === id){ return { ...a, has_viewed:true, unique_views: (v && v.unique_views) ? v.unique_views : a.unique_views }; }
        return a;
      });
      renderList(announcementsCache);

      // If opened from banner, mark banner as dismissed (optional UX)
      if(openFromBanner){
        // do nothing by default; leaving banner until user dismisses is sometimes preferable
      }
    }catch(e){
      detailInner.innerHTML = `<div style="padding:10px; color:#ff9a9a">${escapeHtml(e.message||'Failed to load')}</div>`;
    }
  }

  // Handlers
  bell.onclick = ()=> openOverlay();
  bell.onkeydown = (e)=>{ if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); openOverlay(); } };

  closeBtn && (closeBtn.onclick = closeOverlay);
  overlay.addEventListener('click', (e)=>{ if(e.target === overlay){ closeOverlay(); } });
  backBtn && (backBtn.onclick = showList);
  document.addEventListener('keydown', (e)=>{ if(e.key === 'Escape' && !overlay.classList.contains('apro-hidden')) closeOverlay(); });

  // Boot
  loadAnnouncements().catch(()=>{});
})();
