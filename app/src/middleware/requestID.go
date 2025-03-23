package middleware

import (
	"context"
	"net/http"

	"adaptive-mfa/pkg/common"

	"github.com/google/uuid"
)

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		ctx := context.WithValue(r.Context(), common.ContextKeyRequestID, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
