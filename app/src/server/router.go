package server

import (
	"adaptive-mfa/pkg/common"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
)

type Handler func(http.ResponseWriter, *http.Request)

type HandlerWithMiddlewares struct {
	Handler     interface{}
	Middlewares []Middleware
}

type Router struct {
	routes          map[string]map[string]HandlerWithMiddlewares
	middlewares     []Middleware
	notFoundHandler Handler
}

func NewRouter() *Router {
	return &Router{
		routes:          make(map[string]map[string]HandlerWithMiddlewares),
		middlewares:     []Middleware{},
		notFoundHandler: defaultNotFoundHandler,
	}
}

func (r *Router) NotFound(handler Handler) {
	r.notFoundHandler = handler
}

func (r *Router) addRoute(method, path string, handler interface{}, middlewares ...Middleware) {
	if r.routes[method] == nil {
		r.routes[method] = make(map[string]HandlerWithMiddlewares)
	}
	r.routes[method][path] = HandlerWithMiddlewares{
		Handler:     handler,
		Middlewares: append(r.middlewares, middlewares...),
	}
}

func (r *Router) Group(prefix string) *RouterGroup {
	return &RouterGroup{
		prefix:      prefix,
		router:      r,
		basePath:    "",
		middlewares: r.middlewares,
	}
}

func (r *Router) Get(path string, handler interface{}) {
	r.addRoute(http.MethodGet, path, handler)
}

func (r *Router) Post(path string, handler interface{}) {
	r.addRoute(http.MethodPost, path, handler)
}

func (r *Router) Put(path string, handler interface{}) {
	r.addRoute(http.MethodPut, path, handler)
}

func (r *Router) Delete(path string, handler interface{}) {
	r.addRoute(http.MethodDelete, path, handler)
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	handlerWithMiddlewares, err := r.findHandlerWithMiddlewares(req.Method, req.URL.Path)
	if err != nil {
		r.notFoundHandler(w, req)
		return
	}

	if handler, ok := handlerWithMiddlewares.Handler.(http.Handler); ok {
		Chain(handler.ServeHTTP, handlerWithMiddlewares.Middlewares...)(w, req)
	} else {
		newHandler := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, common.ContextKeyParams, req.URL.Query())
			ctx = context.WithValue(ctx, common.ContextKeyHeaders, req.Header)

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			handler := handlerWithMiddlewares.Handler

			handlerValue := reflect.ValueOf(handler)
			handlerType := reflect.TypeOf(handler)

			if handlerType.NumIn() != 2 {
				http.Error(w, "handler must have 2 arguments", http.StatusInternalServerError)
				return
			}

			reqType := handlerType.In(1)
			req := reflect.New(reqType).Interface()
			if err := json.Unmarshal(body, req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			results := handlerValue.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(req).Elem()})
			if len(results) != 2 {
				http.Error(w, "handler must return 2 values", http.StatusInternalServerError)
				return
			}

			resp := results[0].Interface()
			respErr := results[1].Interface()
			if _err, ok := respErr.(error); ok && respErr != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error": _err.Error(),
				})
				return
			}

			json.NewEncoder(w).Encode(resp)
			w.WriteHeader(http.StatusOK)
		}
		Chain(newHandler, handlerWithMiddlewares.Middlewares...)(w, req)
	}
}

func (r *Router) Use(middleware Middleware) {
	r.middlewares = append(r.middlewares, middleware)
}

func (r *Router) findHandlerWithMiddlewares(method, path string) (HandlerWithMiddlewares, error) {
	if methodRoutes, ok := r.routes[method]; ok {
		if handlerWithMiddlewares, ok := methodRoutes[path]; ok {
			return handlerWithMiddlewares, nil
		}

		for routePath, handlerWithMiddlewares := range methodRoutes {
			if isWildcardMatch(routePath, path) {
				return handlerWithMiddlewares, nil
			}
		}
	}
	return HandlerWithMiddlewares{}, fmt.Errorf("no handler found for %s %s", method, path)
}

func isWildcardMatch(routePath, requestPath string) bool {
	routeParts := strings.Split(routePath, "/")
	requestParts := strings.Split(requestPath, "/")

	if len(routeParts) != len(requestParts) {
		return false
	}

	for i, part := range routeParts {
		if part == "*" {
			continue
		}
		if part != requestParts[i] {
			return false
		}
	}

	return true
}

func defaultNotFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "404 page not found", http.StatusNotFound)
}
