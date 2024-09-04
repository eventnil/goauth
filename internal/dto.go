package internal

import (
	"time"
)

type AccessTokenDTO struct {
	ID             AccessTokenID  `json:"id"`
	RefreshTokenID RefreshTokenID `json:"refresh_token_id"`
	AuthID         AuthID         `json:"value"`
	Role           string         `json:"role"`
	Meta           interface{}    `json:"meta"`
	ExpiresAt      int64          `json:"expires_at"`
	CreatedAt      int64          `json:"created_at"`
}

type AuthenticationDTO struct {
	AuthID    string
	Role      string
	Meta      interface{}
	ExpiresAt int64
}

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
