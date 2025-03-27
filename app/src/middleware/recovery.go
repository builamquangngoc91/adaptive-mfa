package middleware

import (
	"adaptive-mfa/domain"
	"adaptive-mfa/pkg/common"
	"adaptive-mfa/pkg/logger"
	"adaptive-mfa/server"
	"encoding/json"
	"net/http"
)

func RecoveryMiddleware(next server.Handler) server.Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.NewLogger().
					WithContext(r.Context()).
					With("error", err).
					Error("RecoveryMiddleware")

				jsonBody, _ := json.Marshal(&domain.Error{
					Message:   "Internal Server Error",
					Code:      http.StatusInternalServerError,
					RequestID: common.GetRequestID(r.Context()),
				})
				w.WriteHeader(http.StatusInternalServerError)
				w.Write(jsonBody)
			}
		}()
		next(w, r)
	}
}
