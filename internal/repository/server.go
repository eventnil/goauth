package repository

import (
	"github.com/go-redis/redis/v8"
)

type TokenRepository struct {
	IToken IToken
}

func (repository *TokenRepository) Build(
	redisClient *redis.Client,
) {
	redisAdaptor := NewRedisAdaptor(
		redisClient,
	)
	repository.IToken = NewTokenService(
		redisAdaptor,
	)
}
