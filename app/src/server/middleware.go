package server

import "fmt"

type Middleware func(Handler) Handler

func Chain(h Handler, middlewares ...Middleware) Handler {
	fmt.Println("chaining middlewares", len(middlewares))
	for i := len(middlewares) - 1; i >= 0; i-- {
		fmt.Println("chaining middleware", middlewares[i])
		h = middlewares[i](h)
	}
	return h
}
