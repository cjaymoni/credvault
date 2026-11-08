// Runs in <head>, before the body is drawn, so the first frame already has the
// right platform's look rather than flashing a generic one. Kept in its own
// file because the page's CSP does not allow inline scripts.
(function () {
  // `?platform=ios` previews another platform's look in a browser. The
  // shipped app is never opened with a query string, so this changes nothing
  // there.
  let override = null;
  try {
    override = new URLSearchParams(window.location.search).get("platform");
  } catch (_) {
    /* no usable location: detect from the user agent */
  }
  document.documentElement.dataset.platform = Screens.resolvePlatform(
    override,
    navigator.userAgent,
    navigator.maxTouchPoints,
  );
})();
