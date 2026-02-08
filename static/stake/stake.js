(function(){
  const shell = document.getElementById("stakeShell");
  if(!shell) return;

  function setTheme(t){
    shell.setAttribute("data-stake-theme", t);
    localStorage.setItem("stakeTheme", t);
  }
  window.toggleStakeTheme = function(){
    const cur = shell.getAttribute("data-stake-theme") || "dark";
    setTheme(cur === "dark" ? "light" : "dark");
  };
  setTheme(localStorage.getItem("stakeTheme") || "dark");
  // ==================== MOBILE WALLET-BROWSER PROMPT (STAKE) ====================
  const STAKE_MWP_STORAGE_KEY = "stake_mwp_dismissed_at";
  const STAKE_MWP_COOLDOWN_DAYS = 7;

  function stakeMwpIsMobile(){
    const ua = navigator.userAgent || "";
    return /Android|iPhone|iPad|iPod/i.test(ua) || (navigator.maxTouchPoints > 1 && /Macintosh/i.test(ua));
  }
  function stakeMwpHasInjectedProvider(){
    return !!window.ethereum; // staking is EVM-only here
  }
  function stakeMwpInWalletBrowserHeuristic(){
    const ua = (navigator.userAgent || "").toLowerCase();
    if (ua.includes("metamask") || ua.includes("trustwallet")) return true;
    if (window.ethereum && window.ethereum.isMetaMask) return true;
    if (stakeMwpHasInjectedProvider()) return true;
    return false;
  }
  function stakeMwpDismissedRecently(){
    const ts = Number(localStorage.getItem(STAKE_MWP_STORAGE_KEY) || "0");
    if (!ts) return false;
    const ageMs = Date.now() - ts;
    return ageMs < STAKE_MWP_COOLDOWN_DAYS * 24 * 60 * 60 * 1000;
  }

  function maybeShowStakeWalletBrowserPrompt(){
    // Only on /stake routes
    if (!String(window.location.pathname || "").startsWith("/stake")) return;
    if (!stakeMwpIsMobile()) return;
    if (stakeMwpInWalletBrowserHeuristic()) return;
    if (stakeMwpDismissedRecently()) return;
    if (document.getElementById("stake-mwp-root")) return;

    const currentUrl = window.location.href;
    const encodedUrl = encodeURIComponent(currentUrl);

    const metamaskUrl =
      `https://metamask.app.link/dapp/${window.location.host}${window.location.pathname}${window.location.search}${window.location.hash}`;
    const trustUrl =
      `https://link.trustwallet.com/open_url?url=${encodedUrl}`;

    const root = document.createElement("div");
    root.id = "stake-mwp-root";
    root.innerHTML = `
      <div class="mwp-backdrop" role="presentation"></div>
      <div class="mwp-sheet" role="dialog" aria-modal="true" aria-label="Wallet Browser Prompt">
        <div class="mwp-head">
          <div class="mwp-title">Better wallet connection on mobile</div>
          <button class="mwp-x" type="button" aria-label="Close">×</button>
        </div>
        <div class="mwp-body">
          To connect your wallet smoothly, open this page inside your wallet’s built-in browser (MetaMask, Trust Wallet, or any wallet with a browser).
          <div class="mwp-sub">This prevents connection issues in regular mobile browsers.</div>
        </div>
        <div class="mwp-actions">
          <a class="mwp-btn primary" href="${metamaskUrl}" rel="noreferrer noopener">Open in MetaMask</a>
          <a class="mwp-btn primary" href="${trustUrl}" rel="noreferrer noopener">Open in Trust Wallet</a>

          <div class="mwp-copy-group">
            <button class="mwp-btn ghost" type="button" data-mwp-copy>Copy link</button>
            <div class="mwp-copy-hint">Paste inside your wallet browser</div>
          </div>

          <button class="mwp-btn ghost" type="button" data-mwp-continue>Continue in this browser</button>
        </div>
        <div class="mwp-foot">
          <button class="mwp-link" type="button" data-mwp-dontshow>Don’t show again (7 days)</button>
        </div>
      </div>
    `;
    document.body.appendChild(root);

    function close(saveCooldown){
      if (saveCooldown) localStorage.setItem(STAKE_MWP_STORAGE_KEY, String(Date.now()));
      root.remove();
    }

    root.querySelector(".mwp-backdrop").addEventListener("click", ()=>close(false));
    root.querySelector(".mwp-x").addEventListener("click", ()=>close(false));
    root.querySelector("[data-mwp-continue]").addEventListener("click", ()=>close(false));
    root.querySelector("[data-mwp-dontshow]").addEventListener("click", ()=>close(true));

    const copyBtn = root.querySelector("[data-mwp-copy]");
    copyBtn.addEventListener("click", async ()=>{
      try{
        await navigator.clipboard.writeText(window.location.href);
        copyBtn.textContent = "Copied!";
        setTimeout(()=>{ copyBtn.textContent = "Copy link"; }, 1500);
      }catch(e){
        const input=document.createElement("input");
        input.value=window.location.href;
        document.body.appendChild(input);
        input.select();
        document.execCommand("copy");
        document.body.removeChild(input);
        copyBtn.textContent="Copied!";
        setTimeout(()=>{ copyBtn.textContent = "Copy link"; }, 1500);
      }
    });
  }

  // Prompt mobile users to open in wallet browser for best staking UX (after prompt constants are initialized)
  try { maybeShowStakeWalletBrowserPrompt(); } catch (e) {}

function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, (m)=>({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;" }[m]));
  }
  window.stakeToast = function(title, msg, kind){
    const wrap = document.getElementById("stakeToastWrap");
    if(!wrap) return;
    const el = document.createElement("div");
    el.className = "stake-toast " + (kind || "");
    el.innerHTML = `<div class="t-title">${escapeHtml(title)}</div><div class="t-msg">${escapeHtml(msg)}</div>`;
    wrap.appendChild(el);
    setTimeout(()=>{ el.style.opacity="0"; el.style.transform="translateY(6px)"; }, 3800);
    setTimeout(()=>{ el.remove(); }, 4400);
  };

  window.stakeSetBtnLoading = function(btn, loading, label){
    if(!btn) return;
    if(loading){
      btn.disabled = true;
      btn.dataset.prev = btn.innerHTML;
      btn.innerHTML = `<span style="width:14px;height:14px;border:2px solid rgba(255,255,255,.55);border-top-color:rgba(255,255,255,0);border-radius:999px;display:inline-block;animation:stakeSpin .9s linear infinite"></span>` + (label ? `<span>${escapeHtml(label)}</span>` : "");
    }else{
      btn.disabled = false;
      if(btn.dataset.prev) btn.innerHTML = btn.dataset.prev;
    }
  };

  const style = document.createElement("style");
  style.textContent = "@keyframes stakeSpin{to{transform:rotate(360deg)}}";
  document.head.appendChild(style);

  window.decimalToWeiHex = function(amountStr){
    const s = (amountStr || "").trim();
    if(!/^[0-9]+(\.[0-9]+)?$/.test(s)) throw new Error("Invalid amount");
    const parts = s.split(".");
    const intPart = parts[0];
    const fracPart = (parts[1] || "").padEnd(18, "0").slice(0, 18);
    const wei = BigInt(intPart) * (10n ** 18n) + BigInt(fracPart || "0");
    if(wei <= 0n) throw new Error("Amount must be > 0");
    return "0x" + wei.toString(16);
  };

  window.ensureChain = async function(targetChainIdDec){
    const targetHex = "0x" + Number(targetChainIdDec).toString(16);
    const current = await window.ethereum.request({ method: "eth_chainId" });
    if((current||"").toLowerCase() === targetHex.toLowerCase()) return;
    await window.ethereum.request({ method: "wallet_switchEthereumChain", params: [{ chainId: targetHex }] });
  };
})();
