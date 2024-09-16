package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"

	"github.com/c0dev0yager/goauth/internal/domain"
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

func (ra *RedisAdaptor) buildKey(
	key string,
) string {
	return fmt.Sprintf("%s:%v", domain.PkgKeyword, key)
}

func (ra *RedisAdaptor) Set(
	ctx context.Context,
	key string,
	value interface{},
	exp time.Duration,
	pipe redis.Pipeliner,
) error {
	if key == "" || value == nil {
		return nil
	}
	if exp == 0 {
		return errors.New("NonExpiredKeyNotAllowed")
	}
	redisKey := ra.buildKey(key)
	var result *redis.StatusCmd
	if pipe != nil {
		result = pipe.Set(ctx, redisKey, value, exp)
	} else {
		result = ra.redisClient.Set(ctx, redisKey, value, exp)
	}
	return result.Err()
}

func (ra *RedisAdaptor) Get(
	ctx context.Context,
	key string,
) ([]byte, error) {
	redisKey := ra.buildKey(key)
	val, err := ra.redisClient.Get(ctx, redisKey).Result()
	if val == "" {
		return nil, nil
	}
	if val != "" {
		return []byte(val), nil
	}
	return nil, err
}

func (ra *RedisAdaptor) GetMultiple(
	ctx context.Context,
	keys []string,
) ([]interface{}, error) {
	response := make([]interface{}, 0)
	redisKeys := make([]string, len(keys))
	for index, key := range keys {
		redisKeys[index] = ra.buildKey(key)
	}
	val, err := ra.redisClient.MGet(ctx, redisKeys...).Result()
	if errors.Is(err, redis.Nil) {
		return response, nil
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

func (ra *RedisAdaptor) Delete(
	ctx context.Context,
	key string,
) (int64, error) {
	redisKey := ra.buildKey(key)
	val, err := ra.redisClient.Del(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, err
	}
	return val, nil
}

func (ra *RedisAdaptor) DeleteMultiple(
	ctx context.Context,
	keys []string,
) (int64, error) {
	newKeys := make([]string, len(keys))
	for index, key := range keys {
		newKeys[index] = ra.buildKey(key)
	}
	val, err := ra.redisClient.Del(ctx, newKeys...).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, err
	}
	return val, nil
}

func (ra *RedisAdaptor) HSet(
	ctx context.Context,
	hashKey string,
	value map[string]string,
	pipe redis.Pipeliner,
) error {
	redisKey := ra.buildKey(hashKey)
	var err error
	if pipe != nil {
		_, err = pipe.HSet(ctx, redisKey, value).Result()
	} else {
		_, err = ra.redisClient.HSet(ctx, hashKey, value).Result()
	}
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return err
	}
	return nil
}

func (ra *RedisAdaptor) HGet(
	ctx context.Context,
	hashKey string,
	field string,
) ([]byte, error) {
	redisKey := ra.buildKey(hashKey)
	val, err := ra.redisClient.HGet(ctx, redisKey, field).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	return []byte(val), nil
}

func (ra *RedisAdaptor) HMGet(
	ctx context.Context,
	hashKey string,
	fields []string,
) ([]interface{}, error) {
	redisKey := ra.buildKey(hashKey)
	val, err := ra.redisClient.HMGet(ctx, redisKey, fields...).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	return val, nil
}

func (ra *RedisAdaptor) HGetAll(
	ctx context.Context,
	hashKey string,
) (map[string]string, error) {
	redisKey := ra.buildKey(hashKey)
	val, err := ra.redisClient.HGetAll(ctx, redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	return val, nil
}

func (ra *RedisAdaptor) HDelete(
	ctx context.Context,
	hashKey string,
	field []string,
) (int64, error) {
	redisKey := ra.buildKey(hashKey)
	count, err := ra.redisClient.HDel(ctx, redisKey, field...).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}

func (ra *RedisAdaptor) Expire(
	ctx context.Context,
	key string,
	expireIn time.Duration,
	pipe redis.Pipeliner,
) error {
	redisKey := ra.buildKey(key)
	var err error
	if pipe != nil {
		_, err = pipe.Expire(ctx, redisKey, expireIn).Result()
	} else {
		_, err = ra.redisClient.Expire(ctx, redisKey, expireIn).Result()
	}
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return err
	}
	return nil
}

func (ra *RedisAdaptor) ExecuteTransaction(
	ctx context.Context,
	keys []string,
	pipelineFunc func(pipe redis.Pipeliner) error,
) error {
	// Watch the keys before starting the transaction
	err := ra.redisClient.Watch(
		ctx, func(tx *redis.Tx) error {
			// Execute the provided pipeline function inside the transaction
			_, err := tx.Pipelined(
				ctx, func(pipe redis.Pipeliner) error {
					return pipelineFunc(pipe)
				},
			)
			return err
		}, keys...,
	)
	if err != nil {
		return err
	}
	return nil
}
