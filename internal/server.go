package internal

import (
	"github.com/go-redis/redis/v8"

	ra "github.com/c0dev0yager/goauth/internal/repository/adaptors"
	rp "github.com/c0dev0yager/goauth/internal/repository/ports"
	rs "github.com/c0dev0yager/goauth/internal/repository/services"
	ta "github.com/c0dev0yager/goauth/internal/tokens/adaptors"
	tp "github.com/c0dev0yager/goauth/internal/tokens/ports"
	ts "github.com/c0dev0yager/goauth/internal/tokens/services"
)

type TokenContainer struct {
	ITokenPort tp.TokenPort
}

type TokenRepository struct {
	IAccessToken rp.IAccessToken
}

func (container *TokenContainer) Build(
	tr *TokenRepository,
	jwtKey string,
) {
	rep := ta.NewRepositoryAdaptor(tr)
	jwt := ta.NewJwtAdaptor(jwtKey)
	container.ITokenPort = ts.NewTokenService(
		rep,
		jwt,
	)
}

func (repository *TokenRepository) Build(
	redisClient *redis.Client,
) {
	redisAdaptor := ra.NewRedisAdaptor(
		redisClient,
	)
	repository.IAccessToken = rs.NewAccessTokenService(
		redisAdaptor,
	)
}
