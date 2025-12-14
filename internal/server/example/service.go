package example

import (
	"context"
	db "fiber-di-server-template/db/gen/queries.go"
)

type IService interface {
	GetTables(ctx context.Context) ([]db.GetAllTablesRow, error)
}

type Service struct {
	repository IRepository
}

func NewService(repository IRepository) IService {
	s := &Service{
		repository: repository,
	}

	return s
}

func (s *Service) GetTables(ctx context.Context) ([]db.GetAllTablesRow, error) {
	return s.repository.GetTables(ctx)
}
