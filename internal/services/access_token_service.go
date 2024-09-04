package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/c0dev0yager/goauth/internal"
)

type AccessTokenService struct {
	adaptor *adaptor.adaptor
}

func NewAccessTokenService(
	adaptor *adaptor.adaptor,
) *AccessTokenService {
	return &AccessTokenService{
		adaptor: adaptor,
	}
}

func (service *AccessTokenService) buildKey(
	id internal.AccessTokenID,
) string {
	return fmt.Sprintf("rat:%s", id)
}

func (service *AccessTokenService) buildAuthKey(
	id internal.AuthID,
) string {
	return fmt.Sprintf("rai:%s", id)
}

func (service *AccessTokenService) Add(
	ctx context.Context,
	dto internal.AccessTokenDTO,
) (*internal.AccessTokenDTO, error) {
	rid, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	dto.RefreshTokenID = internal.RefreshTokenID(rid.String())

	tid, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	dto.ID = internal.AccessTokenID(tid.String())
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
	id internal.AccessTokenID,
) (*internal.AccessTokenDTO, error) {
	key := service.buildKey(id)
	val, err := service.adaptor.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	dto := internal.AccessTokenDTO{}
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
	id internal.AuthID,
) ([]internal.AccessTokenID, error) {
	key := service.buildAuthKey(id)
	val, err := service.adaptor.HGetAll(ctx, key)
	if err != nil {
		return nil, err
	}
	response := make([]internal.AccessTokenID, 0)
	if val == nil {
		return response, nil
	}
	for tid, _ := range val {
		response = append(response, internal.AccessTokenID(tid))
	}
	return response, nil
}

func (service *AccessTokenService) Delete(
	ctx context.Context,
	id internal.AccessTokenID,
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
	ids []internal.AccessTokenID,
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
