package com.klavyn.desktop

import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.core.graphics.Insets
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

/// The window is edge-to-edge, so the page is drawn underneath the status bar
/// and the navigation bar. CSS is supposed to step around them with
/// `env(safe-area-inset-*)`, but Android's WebView only ever fills those in
/// from a display cutout: a navigation bar is a window inset and never
/// reaches CSS. Every rule that used them therefore computed 0, and the one
/// that showed it was the "New secret" button, drawn behind the navigation
/// bar with its lower half untappable.
///
/// So the insets are measured here and written onto the document as the four
/// `--safe-*` properties that styles.css declares. The CSS falls back to
/// `env()` wherever this does not run, which is every other platform.
class MainActivity : TauriActivity() {
  private companion object {
    /// Must match the name app.js looks for.
    const val BRIDGE_NAME = "__klavynInsets"
  }

  /// Kept so the values can be put back after a reload, which clears
  /// everything this wrote. Insets arrive before the first page is ready, so
  /// they cannot simply be applied once on the way in.
  private var lastInsets: Insets = Insets.NONE

  /// What the bridge hands the page: the four insets in CSS pixels, in CSS
  /// order. Written on the main thread, read on the JavaBridge thread, so it
  /// is @Volatile and immutable rather than four fields read one at a time.
  @Volatile private var cssInsets: String = "0,0,0,0"

  /// WryActivity keeps its own WebView private, so this is the only handle
  /// onResume() has. Cleared in onDestroy() so the activity does not outlive
  /// the view it is holding.
  private var webView: WebView? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onWebViewCreate(webView: WebView) {
    this.webView = webView
    // Pushing alone is not enough: the insets are known before the page
    // exists, and loading it throws away everything written onto the old
    // document. So the page asks as well, once it is ready to be styled.
    webView.addJavascriptInterface(InsetBridge(), BRIDGE_NAME)
    ViewCompat.setOnApplyWindowInsetsListener(webView) { view, windowInsets ->
      // The bars and the cutout together: a landscape cutout is a left or
      // right inset that no bar accounts for.
      lastInsets = windowInsets.getInsets(
        WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
      )
      publishInsets(view as WebView)
      // Returned unconsumed: the activity's own views still need them.
      windowInsets
    }
    // A rotation or a navigation-mode change re-runs the listener; this is
    // for the first layout, which may already have happened.
    ViewCompat.requestApplyInsets(webView)
  }

  override fun onResume() {
    super.onResume()
    // Cheapest way to survive a reload: ask for the insets again, which
    // re-runs the listener and rewrites the properties.
    webView?.let { ViewCompat.requestApplyInsets(it) }
  }

  override fun onDestroy() {
    webView = null
    super.onDestroy()
  }

  /// Read by the page at startup; see applySafeAreaInsets() in app.js. Hands
  /// back the four CSS pixel values in one string, in CSS order, because a
  /// JavaScript interface can only return primitives.
  ///
  /// This runs on the WebView's own JavaBridge thread, not the main thread,
  /// so it reads one @Volatile string and touches no View. Measuring here
  /// would race the main-thread listener that writes the insets and could
  /// hand the page zeros -- which is the bug this class exists to fix, only
  /// intermittent.
  private inner class InsetBridge {
    @JavascriptInterface
    fun cssPixels(): String = cssInsets
  }

  /// Android reports insets in physical pixels; CSS wants density-independent
  /// ones. Written as a plain `px` string because that is what `calc()` in
  /// the stylesheets adds to.
  private fun publishInsets(webView: WebView) {
    val density = webView.resources.displayMetrics.density.takeIf { it > 0f } ?: 1f
    val top = lastInsets.top / density
    val right = lastInsets.right / density
    val bottom = lastInsets.bottom / density
    val left = lastInsets.left / density
    // The one conversion, kept for the bridge to hand over as-is. Computing
    // it twice would mean two copies that have to agree about the order the
    // page unpacks.
    cssInsets = "$top,$right,$bottom,$left"
    webView.evaluateJavascript(
      """
      (function () {
        var root = document.documentElement;
        if (!root) return;
        root.style.setProperty('--safe-top', '${top}px');
        root.style.setProperty('--safe-right', '${right}px');
        root.style.setProperty('--safe-bottom', '${bottom}px');
        root.style.setProperty('--safe-left', '${left}px');
      })();
      """.trimIndent(),
      null,
    )
  }
}
