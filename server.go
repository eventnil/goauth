package goauth

import (
	"github.com/go-redis/redis/v8"

	"github.com/c0dev0yager/goauth/internal/adaptors"
	"github.com/c0dev0yager/goauth/internal/ports"
	"github.com/c0dev0yager/goauth/internal/services"
)

type TokenRepository struct {
	IAccessToken ports.IAccessToken
}

func (repository *TokenRepository) Build(
	redisClient *redis.Client,
) {
	redisAdaptor := adaptor.NewRedisAdaptor(
		redisClient,
	)
	repository.IAccessToken = services.NewAccessTokenService(
		redisAdaptor,
	)
}
