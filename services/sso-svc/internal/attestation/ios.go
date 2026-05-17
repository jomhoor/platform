package attestation

// iOS App Attest verification (M2b).
//
// Implements the verification procedure documented at:
// https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
//
// Wire format (base64-CBOR):
//
//	{
//	  "fmt":      "apple-appattest",
//	  "attStmt":  { "x5c": [<credCertDER>, <caCertDER>], "receipt": <bytes> },
//	  "authData": <bytes>
//	}
//
// authData layout (variable length):
//
//	[0:32]              rpIdHash          (SHA-256 of <teamID>.<bundleID>)
//	[32]                flags             (bits: bit0=UP, bit2=UV, bit6=AT)
//	[33:37]             signCount         (BE uint32, MUST be 0 on first attestation)
//	[37:53]             aaguid            (16 bytes; ASCII "appattestdevelop" or "appattest"+7×0x00)
//	[53:55]             credIdLen         (BE uint16)
//	[55:55+credIdLen]   credentialId      (MUST equal keyId bytes)
//
// Nonce verification (ASN.1 extension OID 1.2.840.113635.100.8.2):
//
//	extension value wraps a SEQUENCE { OCTET STRING { SHA256(authData || clientDataHash) } }

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/pkg/errors"
)

// Apple App Attestation Root CA (P-384).
// Source: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
const appleAppAttestRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

// OID for the Apple App Attest nonce extension: 1.2.840.113635.100.8.2
var appleAttestNonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// aaguid constants.
const (
	aaguidDevelopment = "appattestdevelop" // 16 ASCII bytes
	aaguidProduction  = "appattest"        // 9 ASCII bytes + 7 zero bytes
)

// iosAttestationObj is the top-level CBOR structure returned by
// DCAppAttestService.attestKey on iOS.
type iosAttestationObj struct {
	Fmt      string       `cbor:"fmt"`
	AttStmt  iosAttStmt   `cbor:"attStmt"`
	AuthData []byte       `cbor:"authData"`
}

type iosAttStmt struct {
	X5C     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

// VerifyIOS verifies an Apple App Attest attestation object.
//
//   - attestationB64: base64-encoded CBOR attestation object (from DCAppAttestService.attestKey)
//   - keyID:          base64url-encoded key identifier (from DCAppAttestService.generateKey)
//   - challengeHex:   hex challenge issued by POST /v1/wallets/challenge (0x-prefixed or plain)
//   - cfg:            iOS attestation configuration (team_id, bundle_id, environment)
//
// Returns the keyID string on success (used as the credential identifier).
func VerifyIOS(attestationB64, keyID, challengeHex string, cfg *IOSConfig) (string, error) {
	// --- 1. Decode the CBOR attestation object ---
	raw, err := base64.StdEncoding.DecodeString(attestationB64)
	if err != nil {
		// Try URL-encoding variant (DCAppAttestService returns standard, but be defensive).
		raw, err = base64.URLEncoding.DecodeString(attestationB64)
		if err != nil {
			return "", errors.Wrap(err, "base64 decode attestation")
		}
	}

	var obj iosAttestationObj
	if err := cbor.Unmarshal(raw, &obj); err != nil {
		return "", errors.Wrap(err, "cbor unmarshal attestation")
	}
	if obj.Fmt != "apple-appattest" {
		return "", errors.Errorf("unexpected attestation fmt: %q", obj.Fmt)
	}
	if len(obj.AttStmt.X5C) < 2 {
		return "", errors.New("x5c must contain at least 2 certificates")
	}

	// --- 2. Parse the certificate chain ---
	credCert, err := x509.ParseCertificate(obj.AttStmt.X5C[0])
	if err != nil {
		return "", errors.Wrap(err, "parse credCert")
	}
	intCert, err := x509.ParseCertificate(obj.AttStmt.X5C[1])
	if err != nil {
		return "", errors.Wrap(err, "parse intermediate cert")
	}

	// --- 3. Verify the certificate chain against Apple's root CA ---
	rootPool, err := appleAttestRootPool()
	if err != nil {
		return "", errors.Wrap(err, "build apple root pool")
	}
	intPool := x509.NewCertPool()
	intPool.AddCert(intCert)

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intPool,
	}
	if _, err := credCert.Verify(opts); err != nil {
		return "", errors.Wrap(err, "cert chain verification failed")
	}

	// --- 4. Compute clientDataHash = SHA-256(challengeBytes) ---
	challengeBytes, err := decodeHexChallenge(challengeHex)
	if err != nil {
		return "", errors.Wrap(err, "decode challenge hex")
	}
	clientDataHash := sha256.Sum256(challengeBytes)

	// --- 5. Compute the composite hash and verify the nonce extension ---
	// nonce = SHA-256(authData || clientDataHash)
	composite := append(obj.AuthData, clientDataHash[:]...)
	nonce := sha256.Sum256(composite)

	if err := verifyNonceExtension(credCert, nonce[:]); err != nil {
		return "", errors.Wrap(err, "nonce extension verification failed")
	}

	// --- 6. Verify the public key hash matches the provided keyID ---
	// Apple computes keyId = SHA-256(credCert.SubjectPublicKeyInfo DER bytes),
	// then base64-encodes it.
	ecPub, ok := credCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("credCert public key is not ECDSA")
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(ecPub)
	if err != nil {
		return "", errors.Wrap(err, "marshal credCert SPKI")
	}
	spkiHash := sha256.Sum256(spkiDER)
	computedKeyID := base64.StdEncoding.EncodeToString(spkiHash[:])

	// Accept both standard and URL encoding for the provided keyID.
	normalised := normaliseBase64(keyID)
	if normalised != computedKeyID {
		return "", errors.Errorf("keyId mismatch: client sent %q, derived %q", keyID, computedKeyID)
	}

	// --- 7. Parse authData ---
	authData := obj.AuthData
	if len(authData) < 55 {
		return "", errors.New("authData too short")
	}

	rpIdHash := authData[0:32]
	// flags := authData[32]  // bit-0=UP, bit-2=UV, bit-6=AT (not enforced here)
	signCount := binary.BigEndian.Uint32(authData[33:37])
	aaguid := authData[37:53]
	credIdLen := binary.BigEndian.Uint16(authData[53:55])
	if len(authData) < 55+int(credIdLen) {
		return "", errors.New("authData truncated: credentialId extends beyond buffer")
	}
	credentialID := authData[55 : 55+int(credIdLen)]

	// --- 8. Verify rpIdHash == SHA-256("<teamID>.<bundleID>") ---
	appID := cfg.TeamID + "." + cfg.BundleID
	expectedRpID := sha256.Sum256([]byte(appID))
	if !bytesEqual(rpIdHash, expectedRpID[:]) {
		return "", errors.Errorf("rpIdHash mismatch (expected SHA-256(%q))", appID)
	}

	// --- 9. Verify signCount == 0 (first-time attestation) ---
	if signCount != 0 {
		return "", errors.Errorf("signCount must be 0 on attestation, got %d", signCount)
	}

	// --- 10. Verify aaguid ---
	if err := verifyAAGUID(aaguid, cfg.Environment); err != nil {
		return "", err
	}

	// --- 11. Verify credentialId == keyId bytes ---
	keyIDBytes, err := base64.StdEncoding.DecodeString(computedKeyID)
	if err != nil {
		// Should not happen since we just encoded it.
		return "", errors.Wrap(err, "decode computed keyId")
	}
	if !bytesEqual(credentialID, keyIDBytes) {
		return "", errors.New("credentialId in authData does not match keyId")
	}

	return keyID, nil
}

// verifyNonceExtension checks that the Apple nonce extension in cert contains
// the expected nonce value.
//
// The extension value is DER-encoded as:
//
//	SEQUENCE {
//	  SEQUENCE {
//	    [1] EXPLICIT OCTET STRING { <nonce bytes> }
//	  }
//	}
func verifyNonceExtension(cert *x509.Certificate, expectedNonce []byte) error {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(appleAttestNonceOID) {
			continue
		}
		// The raw extension value is a DER SEQUENCE wrapping a SEQUENCE
		// containing the nonce as a context-tagged OCTET STRING.
		// We unwrap two levels and extract the inner bytes.
		var outer asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &outer); err != nil {
			return errors.Wrap(err, "unmarshal nonce extension outer")
		}
		var inner asn1.RawValue
		if _, err := asn1.Unmarshal(outer.Bytes, &inner); err != nil {
			return errors.Wrap(err, "unmarshal nonce extension inner")
		}
		// inner.Bytes holds the nonce octets.
		if !bytesEqual(inner.Bytes, expectedNonce) {
			return errors.New("nonce extension value does not match expected nonce")
		}
		return nil
	}
	return errors.New("nonce extension (OID 1.2.840.113635.100.8.2) not found in credCert")
}

// verifyAAGUID checks the 16-byte AAGUID field against the expected value for
// the given Apple App Attest environment ("development" or "production").
func verifyAAGUID(aaguid []byte, env string) error {
	var expected [16]byte
	switch strings.ToLower(env) {
	case "development":
		copy(expected[:], []byte(aaguidDevelopment))
	case "production":
		copy(expected[:9], []byte(aaguidProduction))
		// remaining 7 bytes stay zero
	default:
		return errors.Errorf("unknown attestation environment %q (must be 'development' or 'production')", env)
	}
	if !bytesEqual(aaguid, expected[:]) {
		return errors.Errorf("aaguid mismatch for environment %q", env)
	}
	return nil
}

// appleAttestRootPool builds an x509.CertPool containing the Apple App
// Attestation Root CA.
func appleAttestRootPool() (*x509.CertPool, error) {
	block, _ := pem.Decode([]byte(appleAppAttestRootCAPEM))
	if block == nil {
		return nil, errors.New("failed to decode Apple App Attestation Root CA PEM")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse Apple App Attestation Root CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool, nil
}

// normaliseBase64 converts URL-safe base64 (without padding) to standard
// base64 (with padding) so we can compare keyID values regardless of encoding.
func normaliseBase64(s string) string {
	// Replace URL-safe chars with standard chars.
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	// Add padding if needed.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return s
}

// bytesEqual is a constant-time-ish slice comparison (avoids timing side-channels).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
