package internal

import (
	"time"

	"github.com/c0dev0yager/goauth/pkg/domain"
)

type RefreshTokenDTO struct {
	ID        domain.RefreshTokenID `json:"id"`
	ExpiredAt int64                 `json:"expired_at"`
	AuthID    domain.AuthID         `json:"auth_id"`
	CreatedAt int64                 `json:"created_at"`
}

func (entity *RefreshTokenDTO) ToRefreshTokenDTO(
	rid domain.RefreshTokenID,
	dto domain.AccessTokenDTO,
) {
	entity.ID = rid
	entity.AuthID = dto.AuthID
	entity.ExpiredAt = time.Now().UnixMilli()
	entity.CreatedAt = time.Now().UnixMilli()
}
