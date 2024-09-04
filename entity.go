package goauth

import (
	"context"
	"errors"
	"time"

	"github.com/c0dev0yager/goauth/internal"
)

var (
	ErrAuthTokenInvalid   = errors.New("AuthTokenInvalid")
	ErrAuthTokenMalformed = errors.New("AuthTokenInvalid")
	ErrAuthTokenExpired   = errors.New("AuthTokenExpired")
)

type contextKey string

const (
	AuthIDKey               contextKey = "authId"
	AuthRoleKey             contextKey = "authRoleKey"
	TrackingIDContextKey    contextKey = "trackingId"
	LoggerContextKey        contextKey = "httpLogger"
	RequestHeaderContextKey contextKey = "requestHeader"
)

type JWTToken string

type CreateToken struct {
	AuthID   string      `json:"auth_id"`
	Role     string      `json:"role"`
	Meta     interface{} `json:"meta"`
	UniqueID string      `json:"unique_id,omitempty"`
}

func (e *CreateToken) ToCreateAccessToken() internal.AccessTokenDTO {
	dto := internal.AccessTokenDTO{
		AuthID:    internal.AuthID(e.AuthID),
		Role:      e.Role,
		Meta:      e.Meta,
		ExpiresAt: time.Now().UnixMilli(),
		CreatedAt: time.Now().UnixMilli(),
	}
	return dto
}

type InvalidateToken struct {
	AuthID string `json:"auth_id"`
}

type TokenResponseDTO struct {
	AccessToken  JWTToken `json:"access_token"`
	RefreshToken JWTToken `json:"refresh_token"`
	ExpiresAt    int64    `json:"expires_at"`
}

type RequestHeaderDTO struct {
	AuthID     string
	IPv4       string
	DeviceID   string
	Version    string
	TrackingID string
	ClientTime string
}

func GetHeaderDTO(
	ctx context.Context,
) RequestHeaderDTO {
	requestHeaderDTO := RequestHeaderDTO{}
	ctxValue := ctx.Value(RequestHeaderContextKey)
	if ctxValue == nil {
		return requestHeaderDTO
	}
	requestHeaderDTO = ctxValue.(RequestHeaderDTO)
	return requestHeaderDTO
}
