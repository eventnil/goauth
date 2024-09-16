package domain

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenDTO struct {
	ID        TokenID   `json:"id"`
	AuthID    AuthID    `json:"auth_id"`
	Role      string    `json:"role"`
	UniqueID  string    `json:"unique_key"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (entity *TokenDTO) Refresh(
	validityInMinutes time.Duration,
) {
	entity.ID = ""
	entity.ExpiresAt = time.Now().UTC().Add(validityInMinutes)
	entity.CreatedAt = time.Now().UTC()
}

type AuthenticationDTO struct {
	AuthID    string
	Role      string
	Meta      interface{}
	ExpiresAt int64
}

type RefreshTokenDTO struct {
	ID        RefreshID `json:"id"`
	ExpiredAt int64     `json:"expired_at"`
	AuthID    AuthID    `json:"auth_id"`
	CreatedAt int64     `json:"created_at"`
}

func (entity *RefreshTokenDTO) ToRefreshTokenDTO(
	rid RefreshID,
	dto TokenDTO,
) {
	entity.ID = rid
	entity.AuthID = dto.AuthID
	entity.ExpiredAt = time.Now().UnixMilli()
	entity.CreatedAt = time.Now().UnixMilli()
}

type AuthTokenDTO struct {
	AccessToken string
	RefreshKey  string
	ExpiresAt   int64
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

type TokenConfig struct {
	JwtKey            []byte
	EncKey            []byte
	EncIV             []byte
	JwtValidityInMins time.Duration
}
