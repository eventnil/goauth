package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/c0dev0yager/goauth/internal/domain"
	"github.com/c0dev0yager/goauth/internal/repository/adaptors"
)

type AccessTokenService struct {
	adaptor *adaptor.RedisAdaptor
}

func NewAccessTokenService(
	adaptor *adaptor.RedisAdaptor,
) *AccessTokenService {
	return &AccessTokenService{
		adaptor: adaptor,
	}
}

func (service *AccessTokenService) buildKey(
	id domain.AccessTokenID,
) string {
	return fmt.Sprintf("rat:%s", id)
}

func (service *AccessTokenService) buildAuthKey(
	id domain.AuthID,
) string {
	return fmt.Sprintf("rai:%s", id)
}

func (service *AccessTokenService) Add(
	ctx context.Context,
	dto domain.AccessTokenDTO,
) (*domain.AccessTokenDTO, error) {
	rid, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	dto.RefreshTokenID = domain.RefreshTokenID(rid.String())

	tid, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	dto.ID = domain.AccessTokenID(tid.String())
	key := service.buildKey(dto.ID)
	val, err := json.Marshal(dto)
	if err != nil {
		return nil, err
	}

	err = service.adaptor.Set(ctx, key, val, time.Hour*1)
	if err != nil {
		return nil, err
	}

	authKey := service.buildAuthKey(dto.AuthID)
	mapVal := map[string]string{
		tid.String(): rid.String(),
	}
	err = service.adaptor.HSet(ctx, authKey, mapVal)
	if err != nil {
		return nil, err
	}

	return &dto, nil
}

func (service *AccessTokenService) FindById(
	ctx context.Context,
	id domain.AccessTokenID,
) (*domain.AccessTokenDTO, error) {
	key := service.buildKey(id)
	val, err := service.adaptor.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	dto := domain.AccessTokenDTO{}
	err = json.Unmarshal(val, &dto)
	if err != nil {
		return nil, err
	}
	if dto.ID == "" {
		return nil, nil
	}
	return &dto, nil
}

func (service *AccessTokenService) FindByAuthID(
	ctx context.Context,
	id domain.AuthID,
) ([]domain.AccessTokenID, error) {
	key := service.buildAuthKey(id)
	val, err := service.adaptor.HGetAll(ctx, key)
	if err != nil {
		return nil, err
	}
	response := make([]domain.AccessTokenID, 0)
	if val == nil {
		return response, nil
	}
	for tid := range val {
		response = append(response, domain.AccessTokenID(tid))
	}
	return response, nil
}

func (service *AccessTokenService) Delete(
	ctx context.Context,
	id domain.AccessTokenID,
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

func (service *AccessTokenService) MultiDelete(
	ctx context.Context,
	ids []domain.AccessTokenID,
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
