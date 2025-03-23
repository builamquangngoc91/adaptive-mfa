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

func Logger1Middleware(next server.Handler) server.Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request1: %s %s", r.Method, r.URL.Path)
		next(w, r)
		log.Printf("Response1 sent")
	}
}

func Logger2Middleware(next server.Handler) server.Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request2: %s %s", r.Method, r.URL.Path)
		next(w, r)
		log.Printf("Response2 sent")
	}
}
