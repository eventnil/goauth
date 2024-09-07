package domain

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenDTO struct {
	ID            TokenID       `json:"id"`
	RefreshID     RefreshID     `json:"refresh_id"`
	AuthID        AuthID        `json:"auth_id"`
	Role          string        `json:"role"`
	ExpireMinutes time.Duration `json:"minutes"`
	CreatedAt     int64         `json:"created_at"`
}

func (entity *TokenDTO) AddID() error {
	if entity.RefreshID == "" {
		rid, err := uuid.NewUUID()
		if err != nil {
			return err
		}
		entity.RefreshID = RefreshID(rid.String())
	}

	tid, err := uuid.NewUUID()
	if err != nil {
		return err
	}
	entity.ID = TokenID(tid.String())
	return nil
}

func (entity *TokenDTO) FromRefreshToken(
	decryptRefresh string,
) error {
	data := strings.Split(decryptRefresh, "::")
	entity.RefreshID = RefreshID(data[1])
	entity.AuthID = AuthID(data[5])
	entity.Role = data[1]

	tid, err := uuid.NewUUID()
	if err != nil {
		return err
	}
	entity.ID = TokenID(tid.String())
	return nil
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
	RID  string `json:"rid"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

type TokenConfig struct {
	JwtKey            []byte
	EncKey            []byte
	EncIV             []byte
	JwtValidityInMins int
}
