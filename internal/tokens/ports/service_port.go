package ports

import (
	"context"

	domain2 "github.com/c0dev0yager/goauth"
	"github.com/c0dev0yager/goauth/internal"
)

type TokenPort interface {
	Create(
		ctx context.Context,
		rDTO domain2.CreateToken,
	) (*domain2.TokenResponseDTO, error)

	ValidateAccessToken(
		ctx context.Context,
		jwtToken string,
	) (*internal.AccessTokenDTO, error)

	Invalidate(
		ctx context.Context,
		rDTO domain2.InvalidateToken,
	) error
}
