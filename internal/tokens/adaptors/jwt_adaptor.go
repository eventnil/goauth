package adaptors

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	domain2 "github.com/c0dev0yager/goauth"
	internal2 "github.com/c0dev0yager/goauth/internal"
	"github.com/c0dev0yager/goauth/internal/tokens"
)

type JWTAdaptor struct {
	sign string
}

func NewJwtAdaptor(
	jwtSignatureKey string,
) *JWTAdaptor {
	return &JWTAdaptor{
		sign: jwtSignatureKey,
	}
}

func (adaptor *JWTAdaptor) CreateAccessToken(
	ctx context.Context,
	tokenDTO internal2.AccessTokenDTO,
) (domain2.JWTToken, error) {
	current := &jwt.NumericDate{Time: time.Now().UTC()}
	claims := tokens.JWTCustomClaims{
		ID:   string(tokenDTO.ID),
		Role: tokenDTO.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: time.UnixMilli(tokenDTO.ExpiresAt)},
			IssuedAt:  current,
			NotBefore: current,
			Issuer:    "redis-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	accessTokenString, err := token.SignedString(adaptor.sign)
	if err != nil {
		return "", err
	}

	accessToken := domain2.JWTToken(accessTokenString)
	return accessToken, nil
}

func (adaptor *JWTAdaptor) CreateRefreshToken(
	ctx context.Context,
	tokenDTO internal2.AccessTokenDTO,
) (domain2.JWTToken, error) {
	current := &jwt.NumericDate{Time: time.Now().UTC()}
	claims := tokens.JWTCustomClaims{
		ID:   string(tokenDTO.RefreshTokenID),
		Role: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: time.UnixMilli(tokenDTO.ExpiresAt)},
			IssuedAt:  current,
			NotBefore: current,
			Issuer:    "redis-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessTokenString, err := token.SignedString(adaptor.sign)
	if err != nil {
		return "", err
	}

	accessToken := domain2.JWTToken(accessTokenString)
	return accessToken, nil
}

func (adaptor *JWTAdaptor) ValidateJWTToken(
	tokenString string,
) (*tokens.JWTCustomClaims, error) {
	var jwtSignatureKey []byte
	token, err := jwt.ParseWithClaims(
		tokenString, &tokens.JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSignatureKey, nil
		},
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, domain2.ErrAuthTokenExpired
		}
		return nil, domain2.ErrAuthTokenInvalid
	}
	claims, ok := token.Claims.(*tokens.JWTCustomClaims)
	if !ok {
		return nil, domain2.ErrAuthTokenMalformed
	}
	return claims, nil
}
