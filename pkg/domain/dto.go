package domain

type AccessTokenDTO struct {
	ID             AccessTokenID  `json:"id"`
	RefreshTokenID RefreshTokenID `json:"refresh_token_id"`
	AuthID         AuthID         `json:"value"`
	Role           string         `json:"role"`
	Meta           interface{}    `json:"meta"`
	ExpiresAt      int64          `json:"expires_at"`
	CreatedAt      int64          `json:"created_at"`
}

type AuthenticationDTO struct {
	AuthID    string
	Role      string
	Meta      interface{}
	ExpiresAt int64
}
