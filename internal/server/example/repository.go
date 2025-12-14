package example

import (
	"context"
	db "fiber-di-server-template/db/gen/queries.go"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IRepository interface {
	GetTables(ctx context.Context) ([]db.GetAllTablesRow, error)
}

type Repository struct {
	queries *db.Queries
	pool    *pgxpool.Pool
}

func NewRepository(queries *db.Queries, pool *pgxpool.Pool) IRepository {
	r := &Repository{
		queries: queries,
		pool:    pool,
	}

	return r
}

func (r *Repository) GetTables(ctx context.Context) ([]db.GetAllTablesRow, error) {
	return r.queries.GetAllTables(ctx)
}
