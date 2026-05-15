package deeplink

import (
	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/figure"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

// Config holds the values needed to build the wallet-app deep link returned by
// /v1/authorize.
//
// UniversalLinkBase: e.g. "https://sso.jomhoor.org/auth/sso"
//   Used as the primary redirect target. iOS Universal Links / Android App Links
//   intercept this and open the wallet app. If the app is not installed the
//   browser falls through and the user sees the website (which can show a
//   "Get Jomhoor" CTA).
//
// CustomScheme: e.g. "jomhoor"
//   Fallback for local dev / sideloaded builds where Universal Links are not
//   wired (no AASA / assetlinks served on the dev host). Built as
//   "<scheme>://auth/sso?...". Currently only logged for debugging — the
//   primary redirect always uses UniversalLinkBase.
type Config struct {
	UniversalLinkBase string `fig:"universal_link_base,required"`
	CustomScheme      string `fig:"custom_scheme,required"`
}

type Deeplinker interface {
	Deeplink() *Config
}

type deeplinker struct {
	once   comfig.Once
	getter kv.Getter
}

func NewDeeplinker(getter kv.Getter) Deeplinker {
	return &deeplinker{getter: getter}
}

func (d *deeplinker) Deeplink() *Config {
	return d.once.Do(func() interface{} {
		cfg := Config{}
		if err := figure.Out(&cfg).From(kv.MustGetStringMap(d.getter, "deeplink")).Please(); err != nil {
			panic(errors.WithMessage(err, "failed to figure out deeplink config"))
		}
		return &cfg
	}).(*Config)
}
