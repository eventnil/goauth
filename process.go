package goauth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/c0dev0yager/goauth/internal/domain"
)

func recoverHandler(
	next http.HandlerFunc,
) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		defer func() {
			if err := recover(); err != nil {
				logger := domain.Logger()
				logger.Panic(err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode("Unhandled Exception : Panic")
			}
		}()
		next.ServeHTTP(w, r)
	}
}

func loggerMiddleware(
	next http.HandlerFunc,
	topicName string,
) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		logger := domain.Logger()

		dto := GetHeaderDTO(r.Context())
		logFields := logrus.Fields{}
		logFields["topic"] = topicName
		logFields["tracking_id"] = dto.TrackingID
		if dto.ClientTime != "" {
			logFields["x_client_time"] = dto.ClientTime
		}
		if dto.Version != "" {
			logFields["x_version"] = dto.Version
		}
		if dto.DeviceID != "" {
			logFields["x_device_id"] = dto.DeviceID
		}
		if dto.AuthID != "" {
			logFields["auth_id"] = dto.AuthID
		}

		logger.WithFields(logFields)

		contextData := context.WithValue(
			r.Context(),
			LoggerContextKey,
			logger,
		)
		r = r.WithContext(contextData)
		next.ServeHTTP(w, r)
	}
}

func requestMetaMiddleware(
	next http.HandlerFunc,
) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		dto := RequestHeaderDTO{
			TrackingID: uuid.New().String(),
			IPv4:       getIP(r),
		}
		if r.Header.Get("X-Tracking-Id") != "" {
			dto.TrackingID = r.Header.Get("X-Tracking-Id")
		}
		if r.Header.Get("X-Client-Time") != "" {
			dto.ClientTime = r.Header.Get("X-Client-Time")
		}
		if r.Header.Get("X-Version") != "" {
			dto.Version = r.Header.Get("X-Version")
		}
		if r.Header.Get("X-Device-Id") != "" {
			dto.DeviceID = r.Header.Get("X-Device-Id")
		}
		if r.Header.Get("X-Auth-Id") != "" {
			dto.AuthID = r.Header.Get("X-Auth-Id")
		}

		ctx := context.WithValue(r.Context(), RequestHeaderContextKey, dto)
		ctx = context.WithValue(ctx, TrackingIDContextKey, dto.TrackingID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}

func getAuthorizationRoleMap(
	roleString string,
) map[string]bool {
	roles := strings.Split(roleString, ".")
	roleMap := make(map[string]bool)
	for _, role := range roles {
		roleMap[role] = true
	}
	return roleMap
}

func GetID(
	ctx context.Context,
) string {
	return ctx.Value(AuthIDKey).(string)
}

func GetRole(
	ctx context.Context,
) string {
	role := ctx.Value(AuthRoleKey).(string)
	return role
}

func getIP(r *http.Request) string {
	// Get IP from the X-REAL-IP header
	ip := r.Header.Get("X-REAL-IP")
	netIP := net.ParseIP(ip)
	if netIP != nil {
		return ip
	}

	// Get IP from X-FORWARDED-FOR header
	ips := r.Header.Get("X-FORWARDED-FOR")
	splitIps := strings.Split(ips, ",")
	for _, ip := range splitIps {
		netIP := net.ParseIP(ip)
		if netIP != nil {
			return ip
		}
	}

	// Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	netIP = net.ParseIP(ip)
	if netIP != nil {
		return ip
	}
	return ""
}
