package attestation

// shared hex-decode helper used by both iOS and Android verifiers.

import (
	"encoding/hex"
	"strings"

	"github.com/pkg/errors"
)

// decodeHexChallenge converts a hex challenge string (with or without 0x prefix)
// to a byte slice.
func decodeHexChallenge(hexStr string) ([]byte, error) {
	s := strings.TrimPrefix(hexStr, "0x")
	s = strings.TrimPrefix(s, "0X")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrap(err, "hex decode challenge")
	}
	return b, nil
}
