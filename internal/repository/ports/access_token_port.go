package ports

import (
	"context"

	"github.com/c0dev0yager/goauth/internal/domain"
)

type IAccessToken interface {
	Add(
		ctx context.Context,
		dto *domain.TokenDTO,
	) (*domain.TokenDTO, error)

	FindById(
		ctx context.Context,
		id domain.TokenID,
	) (*domain.TokenDTO, error)

	FindByAuthID(
		ctx context.Context,
		id domain.AuthID,
	) ([]domain.TokenID, error)

	Delete(
		ctx context.Context,
		id domain.TokenID,
	) (bool, error)

	MultiDelete(
		ctx context.Context,
		ids []domain.TokenID,
	) (int64, error)
}
