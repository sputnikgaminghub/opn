// Backwards-compatible loader for SEO analytics.
// The SEO templates include /static/analytics.js; keep this file thin.

(function () {
  // If seo.js is bundled separately, load it.
  var s = document.createElement('script');
  s.src = '/static/seo.js';
  s.defer = true;
  document.head.appendChild(s);
})();
