package internal

import (
	"time"
)

type RefreshTokenDTO struct {
	ID        RefreshTokenID `json:"id"`
	ExpiredAt int64          `json:"expired_at"`
	AuthID    AuthID         `json:"auth_id"`
	CreatedAt int64          `json:"created_at"`
}

func (entity *RefreshTokenDTO) ToRefreshTokenDTO(
	rid RefreshTokenID,
	dto AccessTokenDTO,
) {
	entity.ID = rid
	entity.AuthID = dto.AuthID
	entity.ExpiredAt = time.Now().UnixMilli()
	entity.CreatedAt = time.Now().UnixMilli()
}
