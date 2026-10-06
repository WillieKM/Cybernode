// Wires up the mobile hamburger toggle for the shared navbar (components/navbar.html).
// Uses event delegation on document because the navbar markup is injected later via
// fetch().then(html => el.innerHTML = html) — scripts inside that injected HTML never
// run, so the toggle logic has to live in a normally-loaded <script> tag instead.
(function () {
  document.addEventListener('click', function (e) {
    var toggle = e.target.closest('#navToggle');
    var links = document.getElementById('navLinks');
    if (!links) return;

    if (toggle) {
      toggle.classList.toggle('open');
      links.classList.toggle('open');
      document.body.style.overflow = links.classList.contains('open') ? 'hidden' : '';
      return;
    }

    if (e.target.closest('#navLinks a')) {
      var navToggle = document.getElementById('navToggle');
      if (navToggle) navToggle.classList.remove('open');
      links.classList.remove('open');
      document.body.style.overflow = '';
    }
  });
})();

// Analytics loader. The <script> tags inside components/navbar.html never execute
// (they're injected via innerHTML), so Plausible + Vercel Insights were silently
// not loading. nav-toggle.js is included on every page, so load them from here.
(function () {
  if (window.__cnAnalytics) return;
  window.__cnAnalytics = true;
  window.plausible = window.plausible || function () { (window.plausible.q = window.plausible.q || []).push(arguments); };
  window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
  function add(src, attrs) {
    var s = document.createElement('script');
    s.defer = true; s.src = src;
    for (var k in attrs) s.setAttribute(k, attrs[k]);
    document.head.appendChild(s);
  }
  if (/(^|\.)cyber-node\.com$/.test(location.hostname)) {
    add('https://plausible.io/js/script.js', { 'data-domain': 'cyber-node.com' });
    add('/_vercel/insights/script.js', {});
  }
})();
