package repository

import (
	"github.com/go-redis/redis/v8"

	ra "github.com/c0dev0yager/goauth/internal/repository/adaptors"
	rp "github.com/c0dev0yager/goauth/internal/repository/ports"
	rs "github.com/c0dev0yager/goauth/internal/repository/services"
)

type TokenRepository struct {
	IAccessToken rp.IAccessToken
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
