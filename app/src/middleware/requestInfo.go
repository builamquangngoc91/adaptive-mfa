package middleware

import (
	"context"
	"net/http"

	"adaptive-mfa/pkg/common"
	"adaptive-mfa/server"

	"github.com/google/uuid"
)

func RequestInfoMiddleware(next server.Handler) server.Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		ipAddress := r.Header.Get("X-Real-IP")
		if ipAddress == "" {
			ipAddress = r.Header.Get("X-Forwarded-For")
		}
		if ipAddress == "" {
			ipAddress = r.RemoteAddr
		}

		userAgent := r.Header.Get("User-Agent")
		if userAgent == "" {
			userAgent = r.Header.Get("User-Agent")
		}

		deviceID := r.Header.Get("X-Device-ID")
		if deviceID == "" {
			deviceID = r.Header.Get("Device-ID")
		}

		ctx := context.WithValue(r.Context(), common.ContextKeyRequestID, requestID)
		ctx = context.WithValue(ctx, common.ContextKeyIPAddress, ipAddress)
		ctx = context.WithValue(ctx, common.ContextKeyUserAgent, userAgent)
		ctx = context.WithValue(ctx, common.ContextKeyDeviceID, deviceID)
		next(w, r.WithContext(ctx))
	}
}
