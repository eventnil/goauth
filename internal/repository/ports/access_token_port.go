package ports

import (
	"context"

	"github.com/c0dev0yager/goauth/internal"
)

type IAccessToken interface {
	Add(
		ctx context.Context,
		dto internal.AccessTokenDTO,
	) (*internal.AccessTokenDTO, error)

	FindById(
		ctx context.Context,
		id internal.AccessTokenID,
	) (*internal.AccessTokenDTO, error)

	FindByAuthID(
		ctx context.Context,
		id internal.AuthID,
	) ([]internal.AccessTokenID, error)

	Delete(
		ctx context.Context,
		id internal.AccessTokenID,
	) (bool, error)

	MultiDelete(
		ctx context.Context,
		ids []internal.AccessTokenID,
	) (int64, error)
}
