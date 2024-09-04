package ports

import (
	"context"

	"github.com/c0dev0yager/goauth/pkg/domain"
)

type IAccessToken interface {
	Add(
		ctx context.Context,
		dto domain.AccessTokenDTO,
	) (*domain.AccessTokenDTO, error)

	FindById(
		ctx context.Context,
		id domain.AccessTokenID,
	) (*domain.AccessTokenDTO, error)

	FindByAuthID(
		ctx context.Context,
		id domain.AuthID,
	) ([]domain.AccessTokenID, error)

	Delete(
		ctx context.Context,
		id domain.AccessTokenID,
	) (bool, error)

	MultiDelete(
		ctx context.Context,
		ids []domain.AccessTokenID,
	) (int64, error)
}
