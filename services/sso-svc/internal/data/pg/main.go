package pg

import (
	"database/sql"

	"github.com/pkg/errors"
	"gitlab.com/distributed_lab/figure"
	"gitlab.com/distributed_lab/kit/comfig"
	"gitlab.com/distributed_lab/kit/kv"
	_ "github.com/lib/pq"
)

// DB wraps the raw *sql.DB so other packages can call RawDB() for migrations
// and individual query structs for business logic.
type DB struct {
	raw *sql.DB
}

func (d *DB) RawDB() *sql.DB { return d.raw }

type DBer interface {
	DB() *DB
}

type dber struct {
	once   comfig.Once
	getter kv.Getter
}

func NewDBer(getter kv.Getter) DBer {
	return &dber{getter: getter}
}

type dbConfig struct {
	URL string `fig:"url,required"`
}

func (d *dber) DB() *DB {
	return d.once.Do(func() interface{} {
		cfg := dbConfig{}
		if err := figure.Out(&cfg).From(kv.MustGetStringMap(d.getter, "db")).Please(); err != nil {
			panic(errors.WithMessage(err, "failed to figure out db config"))
		}

		db, err := sql.Open("postgres", cfg.URL)
		if err != nil {
			panic(errors.WithMessage(err, "failed to open postgres connection"))
		}

		if err := db.Ping(); err != nil {
			panic(errors.WithMessage(err, "failed to ping postgres"))
		}

		return &DB{raw: db}
	}).(*DB)
}
