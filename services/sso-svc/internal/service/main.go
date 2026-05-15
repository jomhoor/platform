package service

import (
	"net"
	"net/http"

	"github.com/jomhoor/sso-svc/internal/attestation"
	"github.com/jomhoor/sso-svc/internal/config"
	"github.com/jomhoor/sso-svc/internal/cookies"
	"github.com/jomhoor/sso-svc/internal/data/pg"
	"github.com/jomhoor/sso-svc/internal/deeplink"
	"github.com/jomhoor/sso-svc/internal/jwt"
	"github.com/jomhoor/sso-svc/internal/pairwise"
	"gitlab.com/distributed_lab/logan/v3"
)

type service struct {
	log         *logan.Entry
	listener    net.Listener
	jwt         *jwt.JWTIssuer
	pairwise    *pairwise.Deriver
	attestation *attestation.Config
	cookies     *cookies.Cookies
	deeplink    *deeplink.Config
	db          *pg.DB
}

func (s *service) run() error {
	s.log.Info("sso-svc started")
	r := s.router()
	return http.Serve(s.listener, r)
}

func newService(cfg config.Config) *service {
	return &service{
		log:         cfg.Log(),
		listener:    cfg.Listener(),
		jwt:         cfg.JWT(),
		pairwise:    cfg.Pairwise(),
		attestation: cfg.Attestation(),
		cookies:     cfg.Cookies(),
		deeplink:    cfg.Deeplink(),
		db:          cfg.DB(),
	}
}

func Run(cfg config.Config) {
	if err := newService(cfg).run(); err != nil {
		panic(err)
	}
}
