(function(){
  function deviceType(){
    return (window.matchMedia && window.matchMedia('(max-width: 820px)').matches) ? 'mobile' : 'desktop';
  }
  function sourceMedium(){
    try {
      const ref = document.referrer || '';
      if (!ref) return 'direct';
      const u = new URL(ref);
      const host = u.hostname;
      if (host.includes('google.') || host.includes('bing.') || host.includes('duckduckgo.')) return 'organic';
      return 'referral';
    } catch(e){ return 'referral'; }
  }
  function track(name, props){
    const payload = {
      event_name: name,
      page_path: location.pathname,
      page_type: document.body.getAttribute('data-page-type') || 'unknown',
      device_type: deviceType(),
      source_medium: sourceMedium(),
      cta_position: props && props.cta_position ? props.cta_position : undefined,
      props: props || {}
    };
    try {
      if (navigator.sendBeacon) {
        const blob = new Blob([JSON.stringify(payload)], {type:'application/json'});
        navigator.sendBeacon('/api/track-event', blob);
        return;
      }
    } catch(e){}
    fetch('/api/track-event', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)}).catch(()=>{});
  }
  window.trackEvent = track;

  // page view (SEO pages only)
  document.addEventListener('DOMContentLoaded', function(){
    if ((document.body.getAttribute('data-page-type') || '') === 'seo') {
      track('seo_page_view', {});
    }
    document.body.addEventListener('click', function(e){
      const a = e.target.closest('a');
      if (!a) return;
      const cta = a.getAttribute('data-cta');
      if (!cta) return;
      track(cta, {cta_position: a.getAttribute('data-cta-position') || 'unknown', href: a.getAttribute('href')});
    }, {passive:true});
  });
})();
