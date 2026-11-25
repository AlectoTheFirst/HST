// Stamp the theme before first paint. theme.css keys off `data-theme`, so
// without this the page would paint light, then snap to dark once React
// mounts. Loaded as a plain <script src> (not inlined) so it runs under a
// `script-src 'self'` CSP with no 'unsafe-inline' and no hashes: it has to
// execute before the stylesheet paints, not after the module bundle loads.
// Mirrors src/shell/theme.ts; keep the storage key and the resolution rule
// in sync.
(function () {
  var pref = null;
  try {
    pref = localStorage.getItem("hst-theme");
  } catch (e) {
    pref = null;
  }
  var named = ["light", "dark", "dracula", "catppuccin", "tokyo-night", "nord"];
  if (named.indexOf(pref) === -1) {
    pref =
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
  }
  document.documentElement.dataset.theme = pref;
})();
