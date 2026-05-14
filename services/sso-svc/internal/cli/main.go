package cli

import (
	"github.com/alecthomas/kingpin"
	"github.com/jomhoor/sso-svc/internal/assets"
	"github.com/jomhoor/sso-svc/internal/config"
	"github.com/jomhoor/sso-svc/internal/service"
	migrate "github.com/rubenv/sql-migrate"
	"gitlab.com/distributed_lab/kit/kv"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

var migrations = &migrate.EmbedFileSystemMigrationSource{
	FileSystem: assets.Migrations,
	Root:       "migrations",
}

func Run(args []string) bool {
	log := logan.New()

	defer func() {
		if rvr := recover(); rvr != nil {
			log.WithRecover(rvr).Error("app panicked")
		}
	}()

	cfg := config.New(kv.MustFromEnv())
	log = cfg.Log()

	app := kingpin.New("sso-svc", "Jomhoor SSO service")

	runCmd := app.Command("run", "run command")
	serviceCmd := runCmd.Command("service", "run service")

	migrateCmd := app.Command("migrate", "migrate command")
	migrateUpCmd := migrateCmd.Command("up", "apply all pending migrations")
	migrateDownCmd := migrateCmd.Command("down", "roll back last migration batch")

	cmd, err := app.Parse(args[1:])
	if err != nil {
		log.WithError(err).Error("failed to parse arguments")
		return false
	}

	switch cmd {
	case serviceCmd.FullCommand():
		service.Run(cfg)
	case migrateUpCmd.FullCommand():
		if err := migrateUp(cfg); err != nil {
			log.WithError(err).Error("migration up failed")
			return false
		}
	case migrateDownCmd.FullCommand():
		if err := migrateDown(cfg); err != nil {
			log.WithError(err).Error("migration down failed")
			return false
		}
	default:
		log.Errorf("unknown command %s", cmd)
		return false
	}

	return true
}

func migrateUp(cfg config.Config) error {
	applied, err := migrate.Exec(cfg.DB().RawDB(), "postgres", migrations, migrate.Up)
	if err != nil {
		return errors.Wrap(err, "failed to apply migrations")
	}
	cfg.Log().WithField("applied", applied).Info("migrations applied")
	return nil
}

func migrateDown(cfg config.Config) error {
	applied, err := migrate.Exec(cfg.DB().RawDB(), "postgres", migrations, migrate.Down)
	if err != nil {
		return errors.Wrap(err, "failed to roll back migrations")
	}
	cfg.Log().WithField("applied", applied).Info("migrations rolled back")
	return nil
}
