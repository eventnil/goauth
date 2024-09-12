# Go Redis Auth Client

#### GoAuth is a redis client based token managment system which generate short live JWT token and AES encrypted Refresh Token
#### Current version 1.0.0 supports creating single token per auth id

#### Exposed Method:
```sh
CreateToken(
	ctx context.Context,
	dto TokenValue,
) (*TokenResponseDTO, error)
  
RefreshToken(
	ctx context.Context,
	refreshKey string,
	accessToken pkg.JWTToken,
) (*TokenResponseDTO, error)
  
Validate(
	ctx context.Context,
	accessToken pkg.JWTToken,
) (*TokenValue, error)
  
Invalidate(
	ctx context.Context,
	authID string,
) error
```