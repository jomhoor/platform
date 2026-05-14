package handlers

import (
	"encoding/json"
	"net/http"
)

// AppleAppSiteAssociation serves the AASA file required for iOS Universal Links.
// iOS fetches this on every app install from https://sso.jomhoor.org/.well-known/apple-app-site-association.
//
// Fill in the actual team ID and bundle ID (they come from config, but the AASA
// must be a static JSON file, so they are embedded here as constants).
// If these change, update the constants and redeploy — iOS caches AASA for up to 7 days.
//
// Reference: https://developer.apple.com/documentation/xcode/supporting-associated-domains
func AppleAppSiteAssociation(w http.ResponseWriter, r *http.Request) {
	// TEAM_ID.BUNDLE_ID — matches app.config.ts ios.associatedDomains entry.
	const appID = "H2N3RZ4J46.org.jomhoor.app"

	payload := map[string]any{
		"applinks": map[string]any{
			"details": []map[string]any{
				{
					"appIDs": []string{appID},
					"components": []map[string]any{
						{
							// Only intercept the SSO auth path; all other paths fall through to browser.
							"/":       "/auth/sso*",
							"comment": "Jomhoor SSO login deep link",
						},
					},
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	// No-cache: iOS should re-fetch after each deploy.
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		Log(r).WithError(err).Error("failed to write AASA response")
	}
}

// AssetLinks serves the Android App Links verification file.
// Android fetches this from https://sso.jomhoor.org/.well-known/assetlinks.json
// at install time and periodically thereafter.
//
// Fill in sha256_cert_fingerprints: run
//
//	keytool -printcert -jarfile app-release.apk
//
// and paste the SHA-256 fingerprint (colon-separated hex) below.
//
// Reference: https://developer.android.com/training/app-links/verify-android-applinks
func AssetLinks(w http.ResponseWriter, r *http.Request) {
	// Two fingerprints required:
	//   uploadCert    — the upload key used to sign the AAB before uploading to Play.
	//   playSigningCert — the Play-managed signing cert Google uses to re-sign the APK
	//                     delivered to devices. Found in Play Console → Setup → App Signing.
	// Both must be listed so App Links verification passes regardless of which cert the
	// device received (sideloaded/debug vs Play-delivered build).
	const (
		uploadCert      = "BE:41:61:12:AA:21:B6:43:4A:75:D4:DF:B6:4C:0A:2A:EB:47:71:47:D3:9F:16:8D:95:2A:63:EB:FF:02:B5:94"
		playSigningCert = "02:8B:91:97:1D:03:9E:24:71:79:A0:89:BC:FE:A8:43:FF:4E:E8:77:4E:65:C0:24:FF:55:E8:23:5E:15:93:BF"
	)

	payload := []map[string]any{
		{
			"relation": []string{"delegate_permission/common.handle_all_urls"},
			"target": map[string]any{
				"namespace":                "android_app",
				"package_name":             "org.jomhoor.app",
				"sha256_cert_fingerprints": []string{uploadCert, playSigningCert},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		Log(r).WithError(err).Error("failed to write assetlinks response")
	}
}
