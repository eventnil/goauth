package tokens

import (
	"github.com/c0dev0yager/goauth/pkg/repository"
	"github.com/c0dev0yager/goauth/pkg/tokens/internal/adaptors"
	"github.com/c0dev0yager/goauth/pkg/tokens/internal/ports"
	"github.com/c0dev0yager/goauth/pkg/tokens/internal/services"
)

type TokenContainer struct {
	ITokenPort ports.TokenPort
}

func (container *TokenContainer) Build(
	tr *repository.TokenRepository,
	jwtKey string,
) {
	rep := adaptors.NewRepositoryAdaptor(tr)
	jwt := adaptors.NewJwtAdaptor(jwtKey)
	container.ITokenPort = services.NewTokenService(
		rep,
		jwt,
	)
}
