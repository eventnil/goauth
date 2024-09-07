package repository

import (
	"github.com/go-redis/redis/v8"

	"github.com/c0dev0yager/goauth/internal/repository/adaptors"
	"github.com/c0dev0yager/goauth/internal/repository/ports"
	"github.com/c0dev0yager/goauth/internal/repository/services"
)

type TokenRepository struct {
	IAccessToken ports.IAccessToken
}

func (repository *TokenRepository) Build(
	redisClient *redis.Client,
) {
	redisAdaptor := adaptors.NewRedisAdaptor(
		redisClient,
	)
	repository.IAccessToken = services.NewAccessTokenService(
		redisAdaptor,
	)
}
