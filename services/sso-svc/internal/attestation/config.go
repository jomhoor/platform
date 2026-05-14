// Package attestation holds the App Attest (iOS) and Play Integrity (Android)
// configuration. Verification logic for M2 will live in internal/service/handlers/.
package attestation

import (
	"strings"

	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/figure"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type Config struct {
	Enabled bool          `fig:"enabled"`
	IOS     IOSConfig     `fig:"ios"`
	Android AndroidConfig `fig:"android"`
}

type IOSConfig struct {
	TeamID   string `fig:"team_id,required"`
	BundleID string `fig:"bundle_id,required"`
	// Environment is "development" or "production".
	// Development accepts the Apple App Attest development environment
	// (debug builds, TestFlight). Production is for App Store releases.
	Environment string `fig:"environment,required"`
}

type AndroidConfig struct {
	PackageName string `fig:"package_name,required"`
	// SigningCertDigests is a comma-separated list of SHA-256 base64 digests
	// for allowed signing certificates. Must include both the upload cert digest
	// and the Play-managed app signing cert digest.
	SigningCertDigests     string `fig:"signing_cert_digests,required"`
	RequireStrongIntegrity bool   `fig:"require_strong_integrity"`
}

// SigningCertDigestList returns SigningCertDigests parsed into individual entries.
func (a *AndroidConfig) SigningCertDigestList() []string {
	var digests []string
	for _, d := range strings.Split(a.SigningCertDigests, ",") {
		if t := strings.TrimSpace(d); t != "" {
			digests = append(digests, t)
		}
	}
	return digests
}

// Attestationer is implemented by Config and exposed through the service config.
type Attestationer interface {
	Attestation() *Config
}

type attestationer struct {
	once   comfig.Once
	getter kv.Getter
}

func NewAttestationer(getter kv.Getter) Attestationer {
	return &attestationer{getter: getter}
}

func (a *attestationer) Attestation() *Config {
	return a.once.Do(func() interface{} {
		cfg := Config{}
		if err := figure.Out(&cfg).From(kv.MustGetStringMap(a.getter, "app_attestation")).Please(); err != nil {
			panic(errors.WithMessage(err, "failed to figure out app_attestation config"))
		}
		if cfg.Enabled {
			if cfg.IOS.Environment != "development" && cfg.IOS.Environment != "production" {
				panic("app_attestation.ios.environment must be 'development' or 'production'")
			}
		}
		return &cfg
	}).(*Config)
}
