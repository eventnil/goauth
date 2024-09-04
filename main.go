package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"github.com/c0dev0yager/goauth/pkg/domain"
	"github.com/c0dev0yager/goauth/pkg/repository"
	"github.com/c0dev0yager/goauth/pkg/tokens"
)

type Config struct {
	JwtKey string
}

type authClient struct {
	config Config
	redis  *redis.Client
	Tc     *tokens.TokenContainer
}

var cl *authClient

func NewSingletonClient(
	cf Config,
	rs *redis.Client,
) {
	domain.NewLoggerClient(logrus.InfoLevel)

	cl = &authClient{config: cf, redis: rs}

	tr := &repository.TokenRepository{}
	tr.Build(rs)

	tc := &tokens.TokenContainer{}
	tc.Build(tr, cl.config.JwtKey)
	cl.Tc = tc

	domain.Logger().Info("GoAuth: ClientInitialised")
}

func GetClient() *authClient {
	return cl
}

func getFromContext(
	ctx context.Context,
) *logrus.Logger {
	logger, ok := ctx.Value(domain.LoggerContextKey).(logrus.Logger)
	if ok {
		logger.WithField("event", "message")
		return &logger
	}

	newLogger := domain.Logger()
	newLogger.WithField("event", "message")
	return newLogger
}

func (cl *authClient) authenticate(
	next http.Handler,
	roles string,
) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		ctx := r.Context()

		logger := getFromContext(ctx)
		tv := r.Header.Get("Authorization")
		at, err := cl.Tc.ITokenPort.ValidateAccessToken(
			ctx,
			tv,
		)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			if errors.Is(err, domain.ErrAuthTokenExpired) || errors.Is(err, domain.ErrAuthTokenInvalid) || errors.Is(
				err, domain.ErrAuthTokenMalformed,
			) {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(err.Error())
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(err.Error())
		}
		roleMap := getAuthorizationRoleMap(roles)
		_, found := roleMap[at.Role]
		if !found {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode("RoleMismatch")
			return
		}

		ctx = context.WithValue(ctx, domain.AuthIDKey, at.AuthID)
		r = r.WithContext(ctx)

		ctx = context.WithValue(ctx, domain.AuthRoleKey, at.Role)
		r = r.WithContext(ctx)

		headerDTO := domain.GetHeaderDTO(ctx)
		headerDTO.AuthID = string(at.AuthID)

		ctx = context.WithValue(ctx, domain.RequestHeaderContextKey, headerDTO)
		r = r.WithContext(ctx)

		logger.WithField("auth_id", headerDTO.AuthID)
		ctx = context.WithValue(ctx, domain.LoggerContextKey, logger)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	}
}

func AuthenticateMiddleware(
	next http.HandlerFunc,
	roles string,
	topicName string,
) http.HandlerFunc {
	next = recoverHandler(next)
	next = cl.authenticate(next, roles)
	next = loggerMiddleware(next, topicName)
	next = requestMetaMiddleware(next)
	return next
}

func UnauthenticateMiddleware(
	next http.HandlerFunc,
	topicName string,
) http.HandlerFunc {
	next = recoverHandler(next)
	next = loggerMiddleware(next, topicName)
	next = requestMetaMiddleware(next)
	return next
}
