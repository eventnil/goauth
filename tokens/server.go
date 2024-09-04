package tokens

import (
	"github.com/c0dev0yager/goauth"
	adaptors2 "github.com/c0dev0yager/goauth/tokens/internal/adaptors"
	"github.com/c0dev0yager/goauth/tokens/internal/ports"
	"github.com/c0dev0yager/goauth/tokens/internal/services"
)

type TokenContainer struct {
	ITokenPort ports.TokenPort
}

func (container *TokenContainer) Build(
	tr *goauth.TokenRepository,
	jwtKey string,
) {
	rep := adaptors2.NewRepositoryAdaptor(tr)
	jwt := adaptors2.NewJwtAdaptor(jwtKey)
	container.ITokenPort = services.NewTokenService(
		rep,
		jwt,
	)
}
