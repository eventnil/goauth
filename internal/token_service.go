package internal

import (
	"context"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"

	"github.com/c0dev0yager/goauth/internal/domain"
	"github.com/c0dev0yager/goauth/internal/repository"
	"github.com/c0dev0yager/goauth/pkg"
)

type TokenService struct {
	rep *repository.TokenRepository
	cfg domain.TokenConfig
}

func NewTokenService(
	redisClient *redis.Client,
	tokenConfig domain.TokenConfig,
) *TokenService {
	rep := &repository.TokenRepository{}
	rep.Build(redisClient)
	return &TokenService{rep: rep, cfg: tokenConfig}
}

func (s *TokenService) Create(
	ctx context.Context,
	createDTO domain.TokenDTO,
) (*domain.AuthTokenDTO, error) {
	createDTO.UniqueKey = "default"
	refreshKeyVal := fmt.Sprintf("aid::%s::ro::%s::uk::%s", createDTO.AuthID, createDTO.Role, createDTO.UniqueKey)
	rid, err := domain.Aes256Encode(refreshKeyVal, s.cfg.EncKey, s.cfg.EncIV)
	if err != nil {
		return nil, err
	}
	dto, err := s.rep.IToken.Add(
		ctx,
		&createDTO,
	)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.createJWTToken(ctx, *dto)
	if err != nil {
		return nil, err
	}

	res := domain.AuthTokenDTO{
		AccessToken: accessToken,
		RefreshKey:  b64.StdEncoding.EncodeToString([]byte(rid)),
		ExpiresAt:   dto.ExpiresAt.UnixMilli(),
	}

	return &res, nil
}

func (s *TokenService) Refresh(
	ctx context.Context,
	refreshKey string,
	accessToken string,
) (*domain.AuthTokenDTO, error) {
	claim, err := s.decodeAndVerifyJWT(accessToken)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, pkg.ErrAuthTokenMalformed
		}
		if errors.Is(err, jwt.ErrTokenUnverifiable) {
			return nil, pkg.ErrAuthTokenInvalid
		}
		return nil, err
	}

	encodedKey, err := b64.StdEncoding.DecodeString(refreshKey)
	if err != nil {
		return nil, pkg.ErrAuthTokenInvalid
	}
	decryptRefresh, err := domain.Aes256Decode(string(encodedKey), s.cfg.EncKey, s.cfg.EncIV)
	if err != nil {
		return nil, err
	}
	refreshVal := strings.Split(decryptRefresh, "::")

	authID := domain.AuthID(refreshVal[1])
	uniqueKey := refreshVal[5]

	tokenDTO, err := s.rep.IToken.GetByAuthID(ctx, authID, uniqueKey)
	if err != nil {
		return nil, err
	}
	if tokenDTO == nil || string(tokenDTO.ID) != claim.ID {
		return nil, pkg.ErrAuthRefreshKeyInvalid
	}

	tokenDTO.Refresh(s.cfg.JwtValidityInMins)
	tokenDTO, err = s.rep.IToken.Add(ctx, tokenDTO)
	if err != nil {
		return nil, err
	}

	accessToken, err = s.createJWTToken(ctx, *tokenDTO)
	if err != nil {
		return nil, err
	}

	res := domain.AuthTokenDTO{
		AccessToken: accessToken,
		RefreshKey:  b64.StdEncoding.EncodeToString(encodedKey),
		ExpiresAt:   tokenDTO.ExpiresAt.UnixMilli(),
	}

	return &res, nil
}

func (s *TokenService) InvalidateAll(
	ctx context.Context,
	authID domain.AuthID,
) error {
	tokenDTOS, err := s.rep.IToken.FindByAuthID(
		ctx,
		authID,
	)
	if err != nil {
		return err
	}
	if len(tokenDTOS) == 0 {
		return nil
	}
	ids := make([]domain.TokenID, len(tokenDTOS))
	for i, tokenDTO := range tokenDTOS {
		ids[i] = tokenDTO.ID
	}
	_, err = s.rep.IToken.DeleteAuth(ctx, authID)
	if err != nil {
		return err
	}
	_, err = s.rep.IToken.MultiDelete(ctx, ids)
	if err != nil {
		return nil
	}
	return nil
}

func (s *TokenService) ValidateAccessToken(
	ctx context.Context,
	jwtToken string,
) (*domain.TokenDTO, error) {
	claims, err := s.decodeWithClaims(jwtToken)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, pkg.ErrAuthTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, pkg.ErrAuthTokenInvalid
		}
		return nil, err
	}

	at, err := s.rep.IToken.GetById(ctx, domain.TokenID(claims.ID))
	if err != nil {
		return nil, err
	}
	if at == nil {
		return nil, pkg.ErrAuthTokenExpired
	}
	return at, nil
}

func (s *TokenService) createJWTToken(
	ctx context.Context,
	tokenDTO domain.TokenDTO,
) (string, error) {
	current := &jwt.NumericDate{Time: time.Now().UTC()}
	claims := domain.JWTCustomClaims{
		ID:   string(tokenDTO.ID),
		Role: tokenDTO.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: tokenDTO.ExpiresAt},
			IssuedAt:  current,
			NotBefore: current,
			Issuer:    "goauth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	accessToken, err := token.SignedString(s.cfg.JwtKey)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (s *TokenService) decodeWithClaims(
	tokenString string,
) (*domain.JWTCustomClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString, &domain.JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return s.cfg.JwtKey, nil
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
}

func (s *TokenService) decodeAndVerifyJWT(
	tokenString string,
) (*domain.JWTCustomClaims, error) {
	token, err := jwt.Parse(
		tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.cfg.JwtKey, nil
		}, jwt.WithoutClaimsValidation(),
	)
	if err != nil {
		return nil, err
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.ErrTokenMalformed
	}
	claims := domain.JWTCustomClaims{
		ID:   mapClaims["id"].(string),
		Role: mapClaims["role"].(string),
	}
	return &claims, nil
}
