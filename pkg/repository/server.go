package repository

import (
	"github.com/go-redis/redis/v8"

	"github.com/c0dev0yager/goauth/pkg/repository/internal/adaptors"
	"github.com/c0dev0yager/goauth/pkg/repository/internal/ports"
	"github.com/c0dev0yager/goauth/pkg/repository/internal/services"
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
