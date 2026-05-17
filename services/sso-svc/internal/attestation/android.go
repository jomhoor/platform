package attestation

// Android Play Integrity verification (M2b).
//
// Google Play Integrity API docs:
// https://developer.android.com/google/play/integrity/verdict
//
// Flow:
//  1. Client calls IntegrityManagerFactory.create(context).requestIntegrityToken(
//       IntegrityTokenRequest.builder().setNonce(base64(SHA-256(challengeBytes))).build())
//  2. Client sends resulting token to POST /v1/wallets/register.
//  3. Server POSTs to Google's decodeIntegrityToken endpoint (server-side decryption).
//  4. Server verifies: packageName, nonce binding, app recognition verdict,
//     signing cert digest, and optionally device integrity level.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const playIntegrityDecodeURL = "https://playintegrity.googleapis.com/v1/%s:decodeIntegrityToken?key=%s"

// playIntegrityRequest is the body sent to Google's decodeIntegrityToken endpoint.
type playIntegrityRequest struct {
	IntegrityToken string `json:"integrity_token"`
}

// playIntegrityResponse mirrors the tokenPayloadExternal returned by Google.
type playIntegrityResponse struct {
	TokenPayload struct {
		RequestDetails struct {
			RequestPackageName string `json:"requestPackageName"`
			Nonce              string `json:"nonce"`
			TimestampMillis    int64  `json:"timestampMillis"`
		} `json:"requestDetails"`
		AppIntegrity struct {
			AppRecognitionVerdict    string   `json:"appRecognitionVerdict"`
			PackageName              string   `json:"packageName"`
			CertificateSha256Digest  []string `json:"certificateSha256Digest"`
		} `json:"appIntegrity"`
		DeviceIntegrity struct {
			DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
		} `json:"deviceIntegrity"`
	} `json:"tokenPayloadExternal"`
}

// httpClient is package-level so it can be swapped in tests.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// VerifyAndroid verifies a Google Play Integrity token.
//
//   - token:        integrity token from IntegrityManager.requestIntegrityToken
//   - challengeHex: hex challenge from POST /v1/wallets/challenge (0x-prefixed or plain)
//   - cfg:          Android attestation configuration
//
// Returns a credential ID of the form "<packageName>:<firstCertDigest>" on success.
func VerifyAndroid(token, challengeHex string, cfg *AndroidConfig) (string, error) {
	// --- 1. Send token to Google for server-side decryption ---
	url := fmt.Sprintf(playIntegrityDecodeURL, cfg.PackageName, cfg.GoogleAPIKey)

	body, err := json.Marshal(playIntegrityRequest{IntegrityToken: token})
	if err != nil {
		return "", errors.Wrap(err, "marshal play integrity request")
	}

	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return "", errors.Wrap(err, "call play integrity decode endpoint")
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // max 1 MiB
	if err != nil {
		return "", errors.Wrap(err, "read play integrity response")
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("play integrity decode returned HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var payload playIntegrityResponse
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return "", errors.Wrap(err, "unmarshal play integrity response")
	}

	tp := payload.TokenPayload

	// --- 2. Verify package name ---
	if tp.AppIntegrity.PackageName != cfg.PackageName {
		return "", errors.Errorf("packageName mismatch: got %q, want %q",
			tp.AppIntegrity.PackageName, cfg.PackageName)
	}
	if tp.RequestDetails.RequestPackageName != cfg.PackageName {
		return "", errors.Errorf("requestPackageName mismatch: got %q, want %q",
			tp.RequestDetails.RequestPackageName, cfg.PackageName)
	}

	// --- 3. Verify nonce binding: nonce == base64(SHA-256(challengeBytes)) ---
	challengeBytes, err := decodeHexChallenge(challengeHex)
	if err != nil {
		return "", errors.Wrap(err, "decode challenge hex")
	}
	h := sha256.Sum256(challengeBytes)
	expectedNonce := base64.StdEncoding.EncodeToString(h[:])

	if tp.RequestDetails.Nonce != expectedNonce {
		return "", errors.Errorf("nonce mismatch: got %q, want %q", tp.RequestDetails.Nonce, expectedNonce)
	}

	// --- 4. Verify app recognition verdict ---
	if tp.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		return "", errors.Errorf("app recognition verdict is %q (must be PLAY_RECOGNIZED)",
			tp.AppIntegrity.AppRecognitionVerdict)
	}

	// --- 5. Verify signing certificate digest ---
	allowlist := cfg.SigningCertDigestList()
	var matchedDigest string
	for _, got := range tp.AppIntegrity.CertificateSha256Digest {
		for _, allowed := range allowlist {
			if strings.EqualFold(got, allowed) {
				matchedDigest = got
				break
			}
		}
		if matchedDigest != "" {
			break
		}
	}
	if matchedDigest == "" {
		return "", errors.Errorf("none of the signing cert digests %v are in the allowlist", tp.AppIntegrity.CertificateSha256Digest)
	}

	// --- 6. Optionally require MEETS_STRONG_INTEGRITY ---
	if cfg.RequireStrongIntegrity {
		found := false
		for _, verdict := range tp.DeviceIntegrity.DeviceRecognitionVerdict {
			if verdict == "MEETS_STRONG_INTEGRITY" {
				found = true
				break
			}
		}
		if !found {
			return "", errors.Errorf("device does not meet strong integrity (verdicts: %v)",
				tp.DeviceIntegrity.DeviceRecognitionVerdict)
		}
	}

	// Credential ID encodes both the app identity and which signing cert matched.
	credentialID := cfg.PackageName + ":" + matchedDigest
	return credentialID, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
