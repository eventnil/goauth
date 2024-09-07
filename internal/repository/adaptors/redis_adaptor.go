package adaptors

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
)

const (
	goauthRedisKey = "goauth:%v"
)

type RedisAdaptor struct {
	redisClient *redis.Client
}

func NewRedisAdaptor(
	redisClient *redis.Client,
) *RedisAdaptor {
	return &RedisAdaptor{
		redisClient: redisClient,
	}
}

func buildKey(
	key string,
) string {
	return fmt.Sprintf(goauthRedisKey, key)
}

func (adaptor *RedisAdaptor) Set(
	ctx context.Context,
	key string,
	value interface{},
	exp time.Duration,
) error {
	if key == "" || value == nil {
		return nil
	}
	if exp == 0 {
		return errors.New("NonExpiredKeyNotAllowed")
	}
	redisKey := buildKey(key)
	result := adaptor.redisClient.Set(ctx, redisKey, value, exp)
	return result.Err()
}

func (adaptor *RedisAdaptor) Get(
	ctx context.Context,
	key string,
) ([]byte, error) {
	redisKey := buildKey(key)
	val, err := adaptor.redisClient.Get(ctx, redisKey).Result()
	if val == "" {
		return nil, nil
	}
	if val != "" {
		return []byte(val), nil
	}
	return nil, err
}

func (adaptor *RedisAdaptor) GetMultiple(
	ctx context.Context,
	keys []string,
) ([]interface{}, error) {
	response := make([]interface{}, 0)
	redisKeys := make([]string, len(keys))
	for index, key := range keys {
		redisKeys[index] = buildKey(key)
	}
	val, err := adaptor.redisClient.MGet(ctx, redisKeys...).Result()
	if errors.Is(err, redis.Nil) {
		return response, nil
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

func (adaptor *RedisAdaptor) Delete(
	ctx context.Context,
	key string,
) (int64, error) {
	redisKey := buildKey(key)
	val, err := adaptor.redisClient.Del(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, err
	}
	return val, nil
}

func (adaptor *RedisAdaptor) DeleteMultiple(
	ctx context.Context,
	keys []string,
) (int64, error) {
	newKeys := make([]string, len(keys))
	for index, key := range keys {
		newKeys[index] = buildKey(key)
	}
	val, err := adaptor.redisClient.Del(ctx, newKeys...).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, err
	}
	return val, nil
}

func (adaptor *RedisAdaptor) HSet(
	ctx context.Context,
	hashKey string,
	value map[string]string,
) error {
	redisKey := buildKey(hashKey)
	_, err := adaptor.redisClient.HSet(ctx, redisKey, value).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return err
	}
	return nil
}

func (adaptor *RedisAdaptor) HGet(
	ctx context.Context,
	hashKey string,
	field string,
) ([]byte, error) {
	redisKey := buildKey(hashKey)
	val, err := adaptor.redisClient.HGet(ctx, redisKey, field).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	return []byte(val), nil
}

func (adaptor *RedisAdaptor) HMGet(
	ctx context.Context,
	hashKey string,
	fields []string,
) ([]interface{}, error) {
	redisKey := buildKey(hashKey)
	val, err := adaptor.redisClient.HMGet(ctx, redisKey, fields...).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	return val, nil
}

func (adaptor *RedisAdaptor) HGetAll(
	ctx context.Context,
	hashKey string,
) (map[string]string, error) {
	redisKey := buildKey(hashKey)
	val, err := adaptor.redisClient.HGetAll(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	return val, nil
}

func (adaptor *RedisAdaptor) HDelete(
	ctx context.Context,
	hashKey string,
	field []string,
) (int64, error) {
	redisKey := buildKey(hashKey)
	count, err := adaptor.redisClient.HDel(ctx, redisKey, field...).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}
