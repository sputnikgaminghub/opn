
/* Story Mode Theme JS (Warm & Human)
   - Adds scroll-to-chapter behavior + top buttons.
   - Renders a narrative "journey meter" from the same backend-derived data the page already loads.
   - No API changes; we read window.currentUserData when available.
*/
(function(){
  function fmt(n){
    if (n === null || n === undefined || Number.isNaN(n)) return '—';
    try{
      // Use existing formatter if present
      if (typeof window.formatNumber === 'function') return window.formatNumber(Number(n)) + ' OPN';
    }catch(e){}
    const x = Number(n);
    return x.toLocaleString(undefined, {maximumFractionDigits:0}) + ' OPN';
  }

  function safeNum(v){
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  }

  function getClaimData(d){
    return (d && d.claim_data) ? d.claim_data : null;
  }

  function deriveJourney(d){
    const claim = getClaimData(d);

    const base = safeNum((claim && claim.base_amount != null) ? claim.base_amount : d && d.base_amount);
    const referrals = safeNum((claim && claim.referral_count != null) ? claim.referral_count : d && d.referral_count);
    const achievements = safeNum((claim && claim.achievement_rewards != null) ? claim.achievement_rewards : d && d.achievement_rewards);

    // Streak rewards aren't part of the base/referral/achievement airdrop calc in AirdropSystem,
    // but the site has claim-window rewards; we surface it as 0 unless a theme-specific page computes it.
    // If your JS exposes a claimWindowEarned global later, we pick it up.
    const streak = safeNum(window.claimWindowEarned);

    const referralValue = referrals * 121;
    const total = safeNum((claim && claim.amount != null) ? claim.amount : (base + referralValue + achievements));
    const eligible = !!(d && d.eligible);
    const alreadyClaimed = !!(d && d.already_claimed);

    return { base, referrals, referralValue, achievements, streak, total, eligible, alreadyClaimed };
  }

  function setText(id, val){
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = val;
  }

  function updateUI(d){
    const j = deriveJourney(d);

    setText('smTotalValue', fmt(j.total));
    setText('smBaseValue', fmt(j.base));
    setText('smReferralCount', String(j.referrals));
    setText('smReferralValue', fmt(j.referralValue));
    setText('smAchievementValue', fmt(j.achievements));
    setText('smStreakValue', fmt(j.streak));

    const wallet = (window.currentWalletAddress) || (d && d.wallet) || '';
    setText('smWalletLine', 'Wallet: ' + (wallet ? wallet : '—'));

    let status = 'Ready';
    if (j.alreadyClaimed) status = 'Claimed ✓';
    else if (j.eligible) status = 'Eligible ✓';
    else if (d && d.success === false) status = 'Not eligible';
    else if (!wallet) status = 'Connect wallet to begin';
    setText('smStatusLine', 'Status: ' + status);
  }

  function scrollToId(id){
    const el = document.getElementById(id);
    if (!el) return;
    el.scrollIntoView({behavior:'smooth', block:'start'});
  }

  function hookButtons(){
    const topBtn = document.getElementById('smScrollTopBtn');
    if (topBtn){
      topBtn.addEventListener('click', function(){ window.scrollTo({top:0, behavior:'smooth'}); });
    }
    const jump = document.getElementById('smJumpAirdropBtn');
    if (jump){
      jump.addEventListener('click', function(){ scrollToId('airdrop'); });
    }
    const heroStart = document.getElementById('smHeroStartBtn');
    if (heroStart){
      heroStart.addEventListener('click', function(){
        // Focus the existing wallet input if present, otherwise scroll to airdrop.
        const input = document.getElementById('airdropWalletAddress');
        if (input){
          scrollToId('airdrop');
          setTimeout(()=>input.focus(), 250);
        }else{
          scrollToId('airdrop');
        }
      });
    }
  }

  function startPolling(){
    let lastSig = '';
    setInterval(function(){
      const d = window.currentUserData;
      if (!d) return;
      let sig = '';
      try { sig = JSON.stringify({eligible:d.eligible, already_claimed:d.already_claimed, base_amount:d.base_amount, referral_count:d.referral_count, claim_data:d.claim_data}); }
      catch(e){ sig = String(Date.now()); }
      if (sig !== lastSig){
        lastSig = sig;
        updateUI(d);
      }
    }, 450);
  }

  // Slight UX: when a hash link is clicked, close any legacy menus (if present)
  function softenLegacy(){
    try{
      const legacyClose = document.getElementById('closeMenuBtn');
      if (legacyClose) legacyClose.click();
    }catch(e){}
  }

  document.addEventListener('DOMContentLoaded', function(){
    hookButtons();
    softenLegacy();
    // show initial UI if data is already there
    if (window.currentUserData) updateUI(window.currentUserData);
    startPolling();
  });
})();
