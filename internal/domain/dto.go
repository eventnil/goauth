package domain

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
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

type CreateTokenResponseDTO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

type JWTPayload struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	ExpireAt int64  `json:"expireAt"`
}

type JWTCustomClaims struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}
