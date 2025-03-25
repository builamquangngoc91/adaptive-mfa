package middleware

import (
	"adaptive-mfa/server"
	"log"
	"net/http"
)

func LoggerMiddleware(next server.Handler) server.Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		next(w, r)
		log.Printf("Response sent")
	}
}
