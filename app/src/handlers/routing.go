package handlers

import (
	"context"
	"fmt"
	"net/http"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	AuthMiddleware(r.Context())

	handle(w, r)

	HandleError(r.Context())
}

func AuthMiddleware(ctx context.Context) {
	fmt.Println("AuthMiddleware")
}

func HandleError(ctx context.Context) {
	fmt.Println("HandleError")
}

func handle(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handle")
}
