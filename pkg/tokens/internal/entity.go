package internal

import (
	"github.com/golang-jwt/jwt/v5"
)

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
