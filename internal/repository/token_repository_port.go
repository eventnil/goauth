package repository

import (
	"context"

	"github.com/c0dev0yager/goauth/internal/domain"
)

type IToken interface {
	Add(
		ctx context.Context,
		dto *domain.TokenDTO,
	) (*domain.TokenDTO, error)

	GetById(
		ctx context.Context,
		id domain.TokenID,
	) (*domain.TokenDTO, error)

	GetByAuthID(
		ctx context.Context,
		id domain.AuthID,
		field string,
	) (*domain.TokenDTO, error)

	FindByAuthID(
		ctx context.Context,
		id domain.AuthID,
	) ([]domain.TokenDTO, error)

	Delete(
		ctx context.Context,
		id domain.TokenID,
	) (bool, error)

	DeleteAuth(
		ctx context.Context,
		id domain.AuthID,
	) (bool, error)

	MultiDelete(
		ctx context.Context,
		ids []domain.TokenID,
	) (int64, error)

	DeleteAuthFields(
		ctx context.Context,
		authId domain.AuthID,
		fields []string,
	) (int64, error)
}
