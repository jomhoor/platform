package jwt

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/figure"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type Jwter interface {
	JWT() *JWTIssuer
}

type jwter struct {
	once   comfig.Once
	getter kv.Getter
}

func NewJwter(getter kv.Getter) Jwter {
	return &jwter{getter: getter}
}

type jwtConfig struct {
	SecretKey             string        `fig:"secret_key,required"`
	AccessExpirationTime  time.Duration `fig:"access_expiration_time,required"`
	RefreshExpirationTime time.Duration `fig:"refresh_expiration_time,required"`
}

func mustDecodeHex(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(errors.WithMessage(err, "failed to decode hex secret key"))
	}
	return b
}

func (j *jwter) JWT() *JWTIssuer {
	return j.once.Do(func() interface{} {
		cfg := jwtConfig{}
		if err := figure.Out(&cfg).From(kv.MustGetStringMap(j.getter, "jwt")).Please(); err != nil {
			panic(errors.WithMessage(err, "failed to figure out jwt config"))
		}

		return &JWTIssuer{
			prv:               mustDecodeHex(cfg.SecretKey),
			accessExpiration:  cfg.AccessExpirationTime,
			refreshExpiration: cfg.RefreshExpirationTime,
		}
	}).(*JWTIssuer)
}
