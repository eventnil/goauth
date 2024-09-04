package adaptors

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/c0dev0yager/goauth/pkg/domain"
	"github.com/c0dev0yager/goauth/pkg/tokens/internal"
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
	tokenDTO domain.AccessTokenDTO,
) (domain.JWTToken, error) {
	current := &jwt.NumericDate{Time: time.Now().UTC()}
	claims := internal.JWTCustomClaims{
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

	accessToken := domain.JWTToken(accessTokenString)
	return accessToken, nil
}

func (adaptor *JWTAdaptor) CreateRefreshToken(
	ctx context.Context,
	tokenDTO domain.AccessTokenDTO,
) (domain.JWTToken, error) {
	current := &jwt.NumericDate{Time: time.Now().UTC()}
	claims := internal.JWTCustomClaims{
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

	accessToken := domain.JWTToken(accessTokenString)
	return accessToken, nil
}

func (adaptor *JWTAdaptor) ValidateJWTToken(
	tokenString string,
) (*internal.JWTCustomClaims, error) {
	var jwtSignatureKey []byte
	token, err := jwt.ParseWithClaims(
		tokenString, &internal.JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSignatureKey, nil
		},
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, domain.ErrAuthTokenExpired
		}
		return nil, domain.ErrAuthTokenInvalid
	}
	claims, ok := token.Claims.(*internal.JWTCustomClaims)
	if !ok {
		return nil, domain.ErrAuthTokenMalformed
	}
	return claims, nil
}
