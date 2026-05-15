package crypto

import (
	"testing"
)

func TestVerifyWalletSignatureFromApp(t *testing.T) {
	xHex := "0x1f3ef1fd114b6a375a7bd7f940d4b12873afe64de7c8458915d15e087902f2de"
	yHex := "0x2f4ad80d4182380d043f0d9399cae34e70c123935e6707a1e5b2f4df701720be"
	walletAddress := "0x0d938eb61d2669ebcc62d5d95c992dabd8855d9b1d4d3cce086f4630adab4eab"
	challenge := "0x300b10b2d67ef78a1875642e637c0d28499badc2003dd7555653720097cb72c4"
	sig := "0x2c276cdaaad55c7f12edf54dc586174662c119047a2c062606305f1094feb4975618e26226bb42eb8ac6a5b7d9c13b47476fecb662e9ff40ad15d85c7232ba04"

	if err := VerifyWalletAddress(xHex, yHex, walletAddress); err != nil {
		t.Errorf("VerifyWalletAddress failed: %v", err)
	} else {
		t.Log("VerifyWalletAddress: PASS")
	}

	if err := VerifyWalletSignature(xHex, yHex, challenge, sig); err != nil {
		t.Errorf("VerifyWalletSignature failed: %v", err)
	} else {
		t.Log("VerifyWalletSignature: PASS")
	}
}
