package ports

import (
	"context"

	"github.com/c0dev0yager/goauth/pkg/domain"
)

type TokenPort interface {
	Create(
		ctx context.Context,
		rDTO domain.CreateToken,
	) (*domain.TokenResponseDTO, error)

	ValidateAccessToken(
		ctx context.Context,
		jwtToken string,
	) (*domain.AccessTokenDTO, error)

	Invalidate(
		ctx context.Context,
		rDTO domain.InvalidateToken,
	) error
}
