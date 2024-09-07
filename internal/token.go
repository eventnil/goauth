package internal

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"

	"github.com/c0dev0yager/goauth/internal/domain"
	"github.com/c0dev0yager/goauth/internal/repository"
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
	dto, err := s.rep.IAccessToken.Add(
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

	rtd := fmt.Sprintf("rt::%s::ro::%s::aid:%s", dto.RefreshID, dto.Role, dto.AuthID)
	refreshToken, err := domain.Aes256Encode(rtd, s.cfg.EncKey, s.cfg.EncIV)
	if err != nil {
		return nil, err
	}

	res := domain.AuthTokenDTO{
		AccessToken: accessToken,
		RefreshKey:  refreshToken,
		ExpiresAt:   dto.CreatedAt + int64(dto.ExpireMinutes)*60*1000,
	}

	return &res, nil
}

func (s *TokenService) Refresh(
	ctx context.Context,
	refreshKey string,
	accessToken string,
) (*domain.AuthTokenDTO, error) {
	decryptRefresh, err := domain.Aes256Decode(refreshKey, s.cfg.EncKey, s.cfg.EncIV)
	if err != nil {
		return nil, err
	}

	claim, err := s.decodeJWT(accessToken)
	if err != nil {
		return nil, err
	}

	newTokenDTO := &domain.TokenDTO{}
	err = newTokenDTO.FromRefreshToken(decryptRefresh)
	if err != nil {
		return nil, err
	}
	newTokenDTO.ExpireMinutes = time.Duration(s.cfg.JwtValidityInMins) * time.Minute

	if domain.RefreshID(claim.RID) != newTokenDTO.RefreshID {
		return nil, jwt.ErrTokenInvalidId
	}

	dto, err := s.rep.IAccessToken.Add(
		ctx,
		newTokenDTO,
	)
	if err != nil {
		return nil, err
	}

	accessToken, err = s.createJWTToken(ctx, *dto)
	if err != nil {
		return nil, err
	}

	rtd := fmt.Sprintf("rt::%s::ro::%s::aid::%s", dto.RefreshID, dto.Role, dto.AuthID)
	refreshToken, err = domain.Aes256Encode(rtd, s.cfg.EncKey, s.cfg.EncIV)
	if err != nil {
		return nil, err
	}

	res := domain.AuthTokenDTO{
		AccessToken: accessToken,
		RefreshKey:  refreshToken,
		ExpiresAt:   dto.CreatedAt + int64(dto.ExpireMinutes)*60*1000,
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
) (*domain.TokenDTO, error) {
	claims, err := s.decodeJWT(jwtToken)
	if err != nil {
		return nil, err
	}

	at, err := s.rep.IAccessToken.FindById(
		ctx,
		domain.TokenID(claims.ID),
	)
	if err != nil {
		return nil, err
	}
	if at == nil {
		return nil, jwt.ErrTokenExpired
	}
	if at.RefreshID != domain.RefreshID(claims.RID) {
		return nil, jwt.ErrTokenInvalidId
	}
	return at, nil
}

func (s *TokenService) createJWTToken(
	ctx context.Context,
	tokenDTO domain.TokenDTO,
) (string, error) {
	current := &jwt.NumericDate{Time: time.Now().UTC()}
	expireAtMs := tokenDTO.CreatedAt + int64(tokenDTO.ExpireMinutes)*60*1000
	claims := domain.JWTCustomClaims{
		ID:   string(tokenDTO.ID),
		RID:  string(tokenDTO.RefreshID),
		Role: tokenDTO.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: time.UnixMilli(expireAtMs).UTC()},
			IssuedAt:  current,
			NotBefore: current,
			Issuer:    "goauth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	accessToken, err := token.SignedString(s.cfg.JwtKey)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (s *TokenService) decodeJWT(
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
