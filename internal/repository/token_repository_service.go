package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"github.com/c0dev0yager/goauth/internal/domain"
)

type TokenService struct {
	adaptor *RedisAdaptor
}

func NewTokenService(
	adaptor *RedisAdaptor,
) *TokenService {
	return &TokenService{
		adaptor: adaptor,
	}
}

func (s *TokenService) buildKey(
	id domain.TokenID,
) string {
	return fmt.Sprintf("ati:%s", id)
}

func (s *TokenService) buildAuthKey(
	id domain.AuthID,
) string {
	return fmt.Sprintf("aui:%s", id)
}

func (s *TokenService) Add(
	ctx context.Context,
	dto domain.TokenDTO,
) (*domain.TokenDTO, error) {
	tid, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	dto.ID = domain.TokenID(tid.String())

	atKey := s.buildKey(dto.ID)
	atVal, err := json.Marshal(dto)
	if err != nil {
		return nil, err
	}

	atExpireIn := time.Duration(dto.ExpiresAt.Sub(dto.CreatedAt).Minutes()) * time.Minute
	authKey := s.buildAuthKey(dto.AuthID)
	authVal := map[string]string{
		dto.UniqueKey: string(atVal),
	}

	err = s.adaptor.ExecuteTransaction(
		ctx,
		[]string{atKey, authKey},
		func(pipe redis.Pipeliner) error {
			err = s.adaptor.Set(ctx, atKey, atVal, atExpireIn, pipe)
			if err != nil {
				return err
			}
			err = s.adaptor.HSet(ctx, authKey, authVal, pipe)
			if err != nil {
				return err
			}
			// Inactivity for 30 days leads to expire authKey
			err = s.adaptor.Expire(ctx, authKey, 30*24*time.Hour, pipe)
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return &dto, nil
}

func (s *TokenService) GetById(
	ctx context.Context,
	id domain.TokenID,
) (*domain.TokenDTO, error) {
	key := s.buildKey(id)
	val, err := s.adaptor.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if val == nil {
		return nil, nil
	}

	dto := domain.TokenDTO{}
	err = json.Unmarshal(val, &dto)
	if err != nil {
		return nil, err
	}

	if dto.ID == "" {
		return nil, nil
	}
	return &dto, nil
}

func (s *TokenService) GetByAuthID(
	ctx context.Context,
	id domain.AuthID,
	field string,
) (*domain.TokenDTO, error) {
	key := s.buildAuthKey(id)
	val, err := s.adaptor.HGet(ctx, key, field)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}
	dto := domain.TokenDTO{}
	err = json.Unmarshal(val, &dto)
	if err != nil {
		return nil, err
	}
	if dto.ID == "" {
		return nil, nil
	}
	return &dto, nil
}

func (s *TokenService) FindByAuthID(
	ctx context.Context,
	id domain.AuthID,
) ([]domain.TokenDTO, error) {
	key := s.buildAuthKey(id)
	val, err := s.adaptor.HGetAll(ctx, key)
	if err != nil {
		return nil, err
	}

	response := make([]domain.TokenDTO, 0)
	if val == nil {
		return response, nil
	}

	for _, v := range val {
		dto := domain.TokenDTO{}
		err = json.Unmarshal([]byte(v), &dto)
		if err != nil {
			return nil, err
		}
		response = append(response, dto)
	}
	return response, nil
}

func (s *TokenService) Delete(
	ctx context.Context,
	id domain.TokenID,
) (bool, error) {
	key := s.buildKey(id)
	val, err := s.adaptor.Delete(ctx, key)
	if err != nil {
		return false, err
	}

	if val == 0 {
		return false, nil
	}
	return true, nil
}

func (s *TokenService) DeleteAuth(
	ctx context.Context,
	id domain.AuthID,
) (bool, error) {
	key := s.buildAuthKey(id)
	val, err := s.adaptor.Delete(ctx, key)
	if err != nil {
		return false, err
	}

	if val == 0 {
		return false, nil
	}
	return true, nil
}

func (s *TokenService) MultiDelete(
	ctx context.Context,
	ids []domain.TokenID,
) (int64, error) {
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = s.buildKey(id)
	}
	val, err := s.adaptor.DeleteMultiple(ctx, keys)
	if err != nil {
		return 0, err
	}
	return val, nil
}

func (s *TokenService) DeleteAuthFields(
	ctx context.Context,
	authId domain.AuthID,
	fields []string,
) (int64, error) {
	auKey := s.buildAuthKey(authId)
	val, err := s.adaptor.HDelete(ctx, auKey, fields)
	if err != nil {
		return val, err
	}
	return val, nil
}
