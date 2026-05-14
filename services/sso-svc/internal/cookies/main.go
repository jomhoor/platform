package cookies

import (
	"net/http"

	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/figure"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
)

type Cookies struct {
	Domain   string        `fig:"domain,required"`
	Secure   bool          `fig:"secure"`
	SameSite http.SameSite `fig:"same_site"`
}

type Cookier interface {
	Cookies() *Cookies
}

type cookier struct {
	once   comfig.Once
	getter kv.Getter
}

func NewCookier(getter kv.Getter) Cookier {
	return &cookier{getter: getter}
}

func (c *cookier) Cookies() *Cookies {
	return c.once.Do(func() interface{} {
		cfg := Cookies{}
		if err := figure.Out(&cfg).From(kv.MustGetStringMap(c.getter, "cookies")).Please(); err != nil {
			panic(errors.WithMessage(err, "failed to figure out cookies config"))
		}
		return &cfg
	}).(*Cookies)
}
