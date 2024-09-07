package services

import (
	"context"
	"encoding/json"
	"fmt"

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
	id domain.TokenID,
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
	dto *domain.TokenDTO,
) (*domain.TokenDTO, error) {
	err := dto.AddID()
	if err != nil {
		return nil, err
	}

	key := service.buildKey(dto.ID)
	val, err := json.Marshal(dto)
	if err != nil {
		return nil, err
	}

	err = service.adaptor.Set(ctx, key, val, dto.ExpireMinutes)
	if err != nil {
		return nil, err
	}

	authKey := service.buildAuthKey(dto.AuthID)
	mapVal := map[string]string{
		"atid": string(dto.ID),
		"rtid": string(dto.RefreshID),
	}
	err = service.adaptor.HSet(ctx, authKey, mapVal)
	if err != nil {
		return nil, err
	}

	return dto, nil
}

func (service *AccessTokenService) FindById(
	ctx context.Context,
	id domain.TokenID,
) (*domain.TokenDTO, error) {
	key := service.buildKey(id)
	val, err := service.adaptor.Get(ctx, key)
	if err != nil {
		return nil, err
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

func (service *AccessTokenService) FindByAuthID(
	ctx context.Context,
	id domain.AuthID,
) ([]domain.TokenID, error) {
	key := service.buildAuthKey(id)
	val, err := service.adaptor.HGetAll(ctx, key)
	if err != nil {
		return nil, err
	}

	response := make([]domain.TokenID, 0)
	if val == nil {
		return response, nil
	}
	tid, ok := val["atid"]
	if ok {
		response = append(response, domain.TokenID(tid))
	}
	return response, nil
}

func (service *AccessTokenService) Delete(
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

func (service *AccessTokenService) MultiDelete(
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
