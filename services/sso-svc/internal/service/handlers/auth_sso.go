package handlers

import (
	"fmt"
	"net/http"
)

const authSsoFallbackHTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>جمهور — باز کردن اپ</title>
  <style>
    @font-face {
      font-family: 'Nian';
      src: url('/static/fonts/Nian.ttf') format('truetype');
      font-weight: 400;
      font-style: normal;
      font-display: swap;
    }
    @font-face {
      font-family: 'Nian';
      src: url('/static/fonts/NianBold.ttf') format('truetype');
      font-weight: 700;
      font-style: normal;
      font-display: swap;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Nian', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      letter-spacing: 0.04em;
      background: #f5f5f7;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100dvh;
      padding: 1.5rem;
      color: #1d1d1f;
    }

    .card {
      background: #fff;
      border-radius: 1.5rem;
      padding: 2.5rem 2rem;
      width: 100%%;
      max-width: 24rem;
      text-align: center;
      box-shadow: 0 4px 32px rgba(0,0,0,0.08);
    }

    .logo {
      width: clamp(3.5rem, 20vw, 5rem);
      margin-bottom: 1.5rem;
    }

    h1 {
      font-size: clamp(1.15rem, 4vw, 1.4rem);
      font-weight: 700;
      margin-bottom: 0.6rem;
    }

    .subtitle {
      font-size: clamp(0.85rem, 3vw, 0.95rem);
      color: #6e6e73;
      line-height: 1.6;
      margin-bottom: 2rem;
    }

    #open-btn {
      display: block;
      background: #6B4EFF;
      color: #fff;
      font-size: clamp(0.95rem, 3.5vw, 1.05rem);
      font-weight: 600;
      padding: 0.85rem 1.5rem;
      border-radius: 0.875rem;
      text-decoration: none;
      width: 100%%;
      margin-bottom: 2rem;
      transition: opacity 0.15s;
    }
    #open-btn:active { opacity: 0.85; }

    .no-app {
      font-size: 0.85rem;
      color: #6e6e73;
      margin-bottom: 0.875rem;
    }

    .store-links {
      display: flex;
      gap: 0.625rem;
      justify-content: center;
      flex-wrap: wrap;
    }

    .store-links a {
      flex: 1 1 auto;
      min-width: 0;
      max-width: 10rem;
    }

    .store-links a img {
      width: 100%%;
      height: auto;
      display: block;
    }

    /* On narrow phones keep badges from becoming too small */
    @media (max-width: 22rem) {
      .store-links { flex-direction: column; align-items: center; }
      .store-links a { max-width: 9rem; }
    }
  </style>
</head>
<body>
  <div class="card">
    <img
      class="logo"
      src="https://jomhoor.org/images/logo-full.png"
      alt="جمهور"
      onerror="this.style.display='none'"
    />
    <h1>ورود با جمهور</h1>
    <p class="subtitle">برای ادامه، اپ جمهور را روی گوشی‌تان باز کنید.</p>

    <a id="open-btn" href="%s">باز کردن اپ جمهور</a>

    <p class="no-app" id="no-app-hint" style="display:none">
      اپ جمهور را ندارید؟
    </p>
    <div class="store-links" id="store-links" style="display:none">
      <a href="https://apps.apple.com/app/id6770843571" target="_blank" rel="noopener">
        <img src="https://developer.apple.com/assets/elements/badges/download-on-the-app-store.svg" alt="App Store" />
      </a>
      <a href="https://play.google.com/store/apps/details?id=org.jomhoor.app" target="_blank" rel="noopener">
        <img src="https://upload.wikimedia.org/wikipedia/commons/7/78/Google_Play_Store_badge_EN.svg" alt="Google Play" />
      </a>
    </div>
  </div>

  <script>
    // Immediately attempt the custom-scheme deep link.
    window.location.href = %q;

    // After 2 s, if the app didn't open (we're still here), reveal the
    // store links so the user knows how to get the app.
    setTimeout(function () {
      document.getElementById('no-app-hint').style.display = 'block';
      document.getElementById('store-links').style.display  = 'flex';
    }, 2000);
  </script>
</body>
</html>`

// AuthSsoFallback handles GET /auth/sso when iOS Universal Link interception
// fails (e.g. browser-initiated redirect rather than a user tap).
//
// Happy path: iOS intercepts https://sso.jomhoor.org/auth/sso?... before the
// browser makes a network request, opening the Jomhoor wallet app directly.
//
// Fallback path (this handler): the browser actually fetches the URL because
// Universal Links were bypassed (direct navigation, in-app browser, etc.).
// We serve an HTML page that immediately tries the jomhoor:// custom scheme
// and, after 2 s, reveals App Store / Play Store links for users who don't
// have the app installed yet.
func AuthSsoFallback(w http.ResponseWriter, r *http.Request) {
	cfg := Deeplink(r)

	target := cfg.CustomScheme
	if qs := r.URL.RawQuery; qs != "" {
		target += "?" + qs
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, authSsoFallbackHTML, target, target)
}
