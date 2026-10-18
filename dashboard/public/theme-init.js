// Terapkan tema Kumo dari localStorage sebelum paint pertama agar layar tidak berkedip.
// File eksternal (bukan inline) karena CSP backend: script-src 'self'.
(function () {
  var stored = null;
  try { stored = localStorage.getItem('theme'); } catch (e) {}
  var theme = ['light', 'dark', 'system'].indexOf(stored) !== -1 ? stored : 'system';
  var isDark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.setAttribute('data-mode', isDark ? 'dark' : 'light');
})();
