package config

import (
	"github.com/jomhoor/sso-svc/internal/attestation"
	"github.com/jomhoor/sso-svc/internal/cookies"
	"github.com/jomhoor/sso-svc/internal/data/pg"
	"github.com/jomhoor/sso-svc/internal/jwt"
	"github.com/jomhoor/sso-svc/internal/pairwise"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type Config interface {
	comfig.Logger
	comfig.Listenerer
	jwt.Jwter
	pairwise.Pairwiser
	attestation.Attestationer
	cookies.Cookier
	pg.DBer
}

type config struct {
	comfig.Logger
	comfig.Listenerer
	jwt.Jwter
	pairwise.Pairwiser
	attestation.Attestationer
	cookies.Cookier
	pg.DBer
	getter kv.Getter
}

func New(getter kv.Getter) Config {
	return &config{
		getter:        getter,
		Listenerer:    comfig.NewListenerer(getter),
		Logger:        comfig.NewLogger(getter, comfig.LoggerOpts{}),
		Jwter:         jwt.NewJwter(getter),
		Pairwiser:     pairwise.NewPairwiser(getter),
		Attestationer: attestation.NewAttestationer(getter),
		Cookier:       cookies.NewCookier(getter),
		DBer:          pg.NewDBer(getter),
	}
}
