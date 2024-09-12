package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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

func (service *TokenService) buildKey(
	id domain.TokenID,
) string {
	return fmt.Sprintf("ati:%s", id)
}

func (service *TokenService) buildAuthKey(
	id domain.AuthID,
) string {
	return fmt.Sprintf("aui:%s", id)
}

func (service *TokenService) Add(
	ctx context.Context,
	dto *domain.TokenDTO,
) (*domain.TokenDTO, error) {
	tid, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	dto.ID = domain.TokenID(tid.String())
	if err != nil {
		return nil, err
	}

	atKey := service.buildKey(dto.ID)
	val, err := json.Marshal(dto)
	if err != nil {
		return nil, err
	}

	expiryMinute := dto.ExpiresAt.Sub(dto.CreatedAt).Minutes()
	err = service.adaptor.Set(ctx, atKey, val, time.Duration(expiryMinute)*time.Minute)
	if err != nil {
		return nil, err
	}

	authKey := service.buildAuthKey(dto.AuthID)
	mapVal := map[string]string{
		"default": string(val),
	}
	err = service.adaptor.HSet(ctx, authKey, mapVal)
	if err != nil {
		return nil, err
	}
	return dto, nil
}

func (service *TokenService) GetById(
	ctx context.Context,
	id domain.TokenID,
) (*domain.TokenDTO, error) {
	key := service.buildKey(id)
	val, err := service.adaptor.Get(ctx, key)
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

func (service *TokenService) GetByAuthID(
	ctx context.Context,
	id domain.AuthID,
	field string,
) (*domain.TokenDTO, error) {
	key := service.buildAuthKey(id)
	val, err := service.adaptor.HGet(ctx, key, field)
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

func (service *TokenService) FindByAuthID(
	ctx context.Context,
	id domain.AuthID,
) ([]domain.TokenDTO, error) {
	key := service.buildAuthKey(id)
	val, err := service.adaptor.HGetAll(ctx, key)
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

func (service *TokenService) Delete(
	ctx context.Context,
	id domain.TokenID,
) (bool, error) {
	key := service.buildKey(id)
	val, err := service.adaptor.Delete(ctx, key)
	if err != nil {
		return false, err
	}

	if val == 0 {
		return false, nil
	}
	return true, nil
}

func (service *TokenService) DeleteAuth(
	ctx context.Context,
	id domain.AuthID,
) (bool, error) {
	key := service.buildAuthKey(id)
	val, err := service.adaptor.Delete(ctx, key)
	if err != nil {
		return false, err
	}

	if val == 0 {
		return false, nil
	}
	return true, nil
}

func (service *TokenService) MultiDelete(
	ctx context.Context,
	ids []domain.TokenID,
) (int64, error) {
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = service.buildKey(id)
	}
	val, err := service.adaptor.DeleteMultiple(ctx, keys)
	if err != nil {
		return 0, err
	}
	return val, nil
}

func (service *TokenService) DeleteAuthFields(
	ctx context.Context,
	authId domain.AuthID,
	fields []string,
) (int64, error) {
	auKey := service.buildAuthKey(authId)
	val, err := service.adaptor.HDelete(ctx, auKey, fields)
	if err != nil {
		return val, err
	}
	return val, nil
}
