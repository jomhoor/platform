// Package crypto provides BabyJubjub EdDSA and Poseidon verification helpers
// used for wallet registration (M2).
//
// Algorithm contract:
//
//   The app derives its public key as:
//     sk  = beBuff2int(privateKeyBytes)          // BE interpretation of raw 32-byte key
//     pk  = Base8 * sk                           // BabyJubjub scalar multiplication
//     walletAddress = "0x" + beHex(poseidon([pk.x, pk.y]))
//
//   For signing a challenge nonce the app uses a custom EdDSA that keeps sk as-is
//   (no blake512 key derivation, unlike standard iden3 EdDSA):
//     msg  = nonceBigInt % Fp                    // reduce 32-byte nonce to BN254 base field
//     r    = poseidon([sk, msg]) % subOrder       // deterministic nonce
//     R8   = Base8 * r
//     hm   = poseidon([R8.x, R8.y, pk.x, pk.y, msg])
//     S    = (r + 8 * hm * sk) % subOrder       // cofactor 8 to match iden3 VerifyPoseidon
//     sig  = packSignature(R8, S)                // 64 bytes: R8_compressed(32) + S_le(32)
//
//   iden3's VerifyPoseidon checks: S*B8 == R8 + 8*hm*pk (cofactor 8 on the hm*pk term).
//   This works for any BabyJubjub public key, regardless of how the private key was derived,
//   as long as the signing scheme matches this equation.
package crypto

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// bn254Fp is the BN254 base field modulus (Fp).
// Same value used by @iden3/js-crypto's babyJub.F.e() for field reduction.
var bn254Fp, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// VerifyWalletAddress checks that poseidon([xBig, yBig]) == walletAddressHex.
// Inputs are "0x"-prefixed 32-byte hex strings.
// This proves the caller controls the public key that matches the claimed wallet address.
func VerifyWalletAddress(xHex, yHex, walletAddressHex string) error {
	x, ok := hexToBig(xHex)
	if !ok {
		return fmt.Errorf("invalid public_key_x: %q", xHex)
	}
	y, ok := hexToBig(yHex)
	if !ok {
		return fmt.Errorf("invalid public_key_y: %q", yHex)
	}
	expected, ok := hexToBig(walletAddressHex)
	if !ok {
		return fmt.Errorf("invalid wallet_address: %q", walletAddressHex)
	}

	hash, err := poseidon.Hash([]*big.Int{x, y})
	if err != nil {
		return fmt.Errorf("poseidon hash: %w", err)
	}

	if hash.Cmp(expected) != 0 {
		return fmt.Errorf("poseidon([publicKey.x, publicKey.y]) != walletAddress")
	}
	return nil
}

// VerifyWalletSignature verifies the BabyJubjub EdDSA signature over the
// registration challenge nonce.
//
// xHex, yHex    — stored public key coordinates ("0x"-prefixed hex, 32 bytes each).
// nonceHex      — the challenge nonce ("0x"-prefixed hex, 32 bytes).
// sigHex        — packed 64-byte signature ("0x"-prefixed hex, 128 hex chars).
func VerifyWalletSignature(xHex, yHex, nonceHex, sigHex string) error {
	x, ok := hexToBig(xHex)
	if !ok {
		return fmt.Errorf("invalid public_key_x: %q", xHex)
	}
	y, ok := hexToBig(yHex)
	if !ok {
		return fmt.Errorf("invalid public_key_y: %q", yHex)
	}

	// Reduce nonce to Fp element (mirrors JS: babyJub.F.e(nonceBigInt)).
	nonceBytes, err := hex.DecodeString(strings.TrimPrefix(nonceHex, "0x"))
	if err != nil {
		return fmt.Errorf("decode nonce hex: %w", err)
	}
	nonceBig := new(big.Int).SetBytes(nonceBytes) // big-endian
	msg := new(big.Int).Mod(nonceBig, bn254Fp)

	// Decode packed signature (64 bytes).
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil {
		return fmt.Errorf("decode signature hex: %w", err)
	}
	if len(sigBytes) != 64 {
		return fmt.Errorf("signature must be 64 bytes, got %d", len(sigBytes))
	}

	var sigComp babyjub.SignatureComp
	copy(sigComp[:], sigBytes)
	sig, err := sigComp.Decompress()
	if err != nil {
		return fmt.Errorf("decompress signature: %w", err)
	}

	pk := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	if !pk.VerifyPoseidon(msg, sig) {
		return fmt.Errorf("wallet signature verification failed")
	}
	return nil
}

func hexToBig(h string) (*big.Int, bool) {
	h = strings.TrimPrefix(h, "0x")
	b := new(big.Int)
	_, ok := b.SetString(h, 16)
	return b, ok
}
