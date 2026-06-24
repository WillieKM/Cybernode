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
