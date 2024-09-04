package internal

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"

	"github.com/c0dev0yager/goauth/internal/domain"
	"github.com/c0dev0yager/goauth/internal/repository"
)

type TokenService struct {
	rep  *repository.TokenRepository
	sign []byte
}

func NewTokenService(
	redisClient *redis.Client,
	jwtKey string,
) *TokenService {
	rep := &repository.TokenRepository{}
	rep.Build(redisClient)
	return &TokenService{rep: rep, sign: []byte(jwtKey)}
}

func (s *TokenService) Create(
	ctx context.Context,
	createDTO domain.AccessTokenDTO,
) (*domain.CreateTokenResponseDTO, error) {
	dto, err := s.rep.IAccessToken.Add(
		ctx,
		createDTO,
	)
	if err != nil {
		return nil, err
	}

	jwtAccess, err := s.createAccessToken(ctx, *dto)
	if err != nil {
		return nil, err
	}
	jwtRefresh, err := s.createRefreshToken(ctx, *dto)
	if err != nil {
		return nil, err
	}
	res := domain.CreateTokenResponseDTO{
		AccessToken:  jwtAccess,
		RefreshToken: jwtRefresh,
		ExpiresAt:    dto.ExpiresAt,
	}

	return &res, nil
}

func (s *TokenService) Invalidate(
	ctx context.Context,
	authID domain.AuthID,
) error {
	ids, err := s.rep.IAccessToken.FindByAuthID(
		ctx,
		authID,
	)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	_, err = s.rep.IAccessToken.MultiDelete(
		ctx,
		ids,
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *TokenService) ValidateAccessToken(
	ctx context.Context,
	jwtToken string,
) (*domain.AccessTokenDTO, error) {
	claims, err := s.validateJWT(jwtToken)
	if err != nil {
		return nil, err
	}

	at, err := s.rep.IAccessToken.FindById(
		ctx,
		domain.AccessTokenID(claims.ID),
	)
	if err != nil {
		return nil, err
	}
	if at == nil {
		return nil, jwt.ErrTokenExpired
	}
	return at, nil
}

func (s *TokenService) createAccessToken(
	ctx context.Context,
	tokenDTO domain.AccessTokenDTO,
) (string, error) {
	current := &jwt.NumericDate{Time: time.Now().UTC()}
	claims := domain.JWTCustomClaims{
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

	accessToken, err := token.SignedString(s.sign)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (s *TokenService) createRefreshToken(
	ctx context.Context,
	tokenDTO domain.AccessTokenDTO,
) (string, error) {
	current := &jwt.NumericDate{Time: time.Now().UTC()}
	claims := domain.JWTCustomClaims{
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
	refreshToken, err := token.SignedString(s.sign)
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

func (s *TokenService) validateJWT(
	tokenString string,
) (*domain.JWTCustomClaims, error) {
	var jwtSignatureKey []byte
	token, err := jwt.ParseWithClaims(
		tokenString, &domain.JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSignatureKey, nil
		},
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*domain.JWTCustomClaims)
	if !ok {
		return nil, jwt.ErrTokenMalformed
	}
	return claims, nil

	// if err != nil {
	// 	if errors.Is(err, jwt.ErrTokenExpired) {
	// 		return nil, internal.ErrAuthTokenExpired
	// 	}
	// 	return nil, domain2.ErrAuthTokenInvalid
	// }
	// claims, ok := token.Claims.(*JWTCustomClaims)
	// if !ok {
	// 	return nil, domain2.ErrAuthTokenMalformed
	// }
	// return claims, nil
}
