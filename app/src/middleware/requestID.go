package middleware

import (
	"context"
	"net/http"

	"adaptive-mfa/pkg/common"
	"adaptive-mfa/server"

	"github.com/google/uuid"
)

func RequestIDMiddleware(next server.Handler) server.Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		ctx := context.WithValue(r.Context(), common.ContextKeyRequestID, requestID)
		next(w, r.WithContext(ctx))
	}
}
