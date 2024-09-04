package goauth

import (
	"github.com/c0dev0yager/goauth/internal/tokens/adaptors"
	"github.com/c0dev0yager/goauth/internal/tokens/ports"
	"github.com/c0dev0yager/goauth/internal/tokens/services"
)

type TokenContainer struct {
	ITokenPort ports.TokenPort
}

func (container *TokenContainer) build(
	tr *TokenRepository,
	jwtKey string,
) {
	rep := adaptors.NewRepositoryAdaptor(tr)
	jwt := adaptors.NewJwtAdaptor(jwtKey)
	container.ITokenPort = services.NewTokenService(
		rep,
		jwt,
	)
}
