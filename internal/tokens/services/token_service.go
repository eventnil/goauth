package services

import (
	"context"

	domain2 "github.com/c0dev0yager/goauth"
	"github.com/c0dev0yager/goauth/internal"
	"github.com/c0dev0yager/goauth/internal/tokens/adaptors"
)

type TokenService struct {
	rep *adaptors.RepositoryAdaptor
	jwt *adaptors.JWTAdaptor
}

func NewTokenService(
	rep *adaptors.RepositoryAdaptor,
	jwt *adaptors.JWTAdaptor,
) *TokenService {
	return &TokenService{rep: rep, jwt: jwt}
}

func (s *TokenService) Create(
	ctx context.Context,
	rDTO domain2.CreateToken,
) (*domain2.TokenResponseDTO, error) {
	createTokenDTO := rDTO.ToCreateAccessToken()
	dto, err := s.rep.Token().IAccessToken.Add(
		ctx,
		createTokenDTO,
	)
	if err != nil {
		return nil, err
	}

	jwtAccess, err := s.jwt.CreateAccessToken(ctx, *dto)
	if err != nil {
		return nil, err
	}
	jwtRefresh, err := s.jwt.CreateRefreshToken(ctx, *dto)
	if err != nil {
		return nil, err
	}
	res := domain2.TokenResponseDTO{
		AccessToken:  jwtAccess,
		RefreshToken: jwtRefresh,
		ExpiresAt:    dto.ExpiresAt,
	}

	return &res, nil
}

func (s *TokenService) Invalidate(
	ctx context.Context,
	rDTO domain2.InvalidateToken,
) error {
	ids, err := s.rep.Token().IAccessToken.FindByAuthID(
		ctx,
		internal.AuthID(rDTO.AuthID),
	)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	_, err = s.rep.Token().IAccessToken.MultiDelete(
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
) (*internal.AccessTokenDTO, error) {
	claims, err := s.jwt.ValidateJWTToken(jwtToken)
	if err != nil {
		return nil, err
	}
	at, err := s.rep.Token().IAccessToken.FindById(
		ctx,
		internal.AccessTokenID(claims.ID),
	)
	if err != nil {
		return nil, err
	}
	if at == nil {
		return nil, domain2.ErrAuthTokenExpired
	}
	return at, nil
}
