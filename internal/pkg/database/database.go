package database

import (
	"context"
	db "fiber-di-server-template/db/gen/queries.go"
	"fiber-di-server-template/internal/pkg/config"
	"github.com/amacneil/dbmate/v2/pkg/dbmate"
	_ "github.com/amacneil/dbmate/v2/pkg/driver/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"
	"net/url"
)

func NewDatabase(lc fx.Lifecycle, cfg *config.Config) (*pgxpool.Pool, error) {

	pool, err := pgxpool.New(context.Background(), cfg.Database.DataBaseUrl)

	if err != nil {
		return nil, err
	}

	if err = pool.Ping(context.Background()); err != nil {
		return nil, err
	}

	lc.Append(fx.Hook{
		OnStop: func(ctx context.Context) error {
			pool.Close()
			return nil
		},
	})

	return pool, nil
}

func NewQueries(database *pgxpool.Pool) *db.Queries {
	return db.New(database)
}

func Migrate(cfg *config.Config) error {
	u, err := url.Parse(cfg.Database.DataBaseUrl)
	if err != nil {
		return err
	}

	conn := dbmate.New(u)

	return conn.Migrate()
}

var Module = fx.Options(
	fx.Provide(NewDatabase),
	fx.Provide(NewQueries),
	fx.Invoke(Migrate),
)
