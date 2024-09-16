package pkg

import (
	"encoding/json"
	"errors"
)

var (
	ErrFieldValidation       = errors.New("ErrFieldValidation")
	ErrAuthTokenInvalid      = errors.New("AuthTokenInvalid")
	ErrAuthTokenMalformed    = errors.New("AuthTokenMalformed")
	ErrAuthTokenExpired      = errors.New("AuthTokenExpired")
	ErrAuthRefreshKeyInvalid = errors.New("AuthRefreshKeyInvalid")
)

type JWTToken string

func MapToString(
	mapData interface{},
) string {
	data, err := json.Marshal(mapData)
	if err != nil {
		return ""
	}
	return string(data)
}
