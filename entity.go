package goauth

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/c0dev0yager/goauth/internal/domain"
	"github.com/c0dev0yager/goauth/pkg"
)

type contextKey string

const (
	AuthIDKey               contextKey = "authId"
	AuthRoleKey             contextKey = "authRoleKey"
	TrackingIDContextKey    contextKey = "trackingId"
	LoggerContextKey        contextKey = "httpLogger"
	RequestHeaderContextKey contextKey = "requestHeader"
)

type TokenValue struct {
	AuthID string `json:"auth_id"`
	Role   string `json:"role"`
}

func (e *TokenValue) ToInternalToken() domain.TokenDTO {
	dto := domain.TokenDTO{
		AuthID:    domain.AuthID(e.AuthID),
		Role:      e.Role,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Duration(cl.config.JwtValidityInMins) * time.Minute),
	}

	return dto
}

type InvalidateToken struct {
	AuthID string `json:"auth_id"`
}

type TokenResponseDTO struct {
	AccessToken pkg.JWTToken `json:"access_token"`
	RefreshKey  string       `json:"refresh_key"`
	ExpiresAt   int64        `json:"expires_at"`
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

func GetID(
	ctx context.Context,
) string {
	return ctx.Value(AuthIDKey).(string)
}

func GetRole(
	ctx context.Context,
) string {
	role := ctx.Value(AuthRoleKey).(string)
	return role
}

func getIP(r *http.Request) string {
	// Get IP from the X-REAL-IP header
	ip := r.Header.Get("X-REAL-IP")
	netIP := net.ParseIP(ip)
	if netIP != nil {
		return ip
	}

	// Get IP from X-FORWARDED-FOR header
	ips := r.Header.Get("X-FORWARDED-FOR")
	splitIps := strings.Split(ips, ",")
	for _, ip := range splitIps {
		netIP := net.ParseIP(ip)
		if netIP != nil {
			return ip
		}
	}

	// Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	netIP = net.ParseIP(ip)
	if netIP != nil {
		return ip
	}
	return ""
}
