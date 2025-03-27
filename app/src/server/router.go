package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"runtime/debug"
	"strings"

	"adaptive-mfa/domain"
	"adaptive-mfa/pkg/common"
	appError "adaptive-mfa/pkg/error"
	"adaptive-mfa/pkg/logger"
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

			handler := handlerWithMiddlewares.Handler

			handlerValue := reflect.ValueOf(handler)
			handlerType := reflect.TypeOf(handler)

			var (
				body []byte
				in   []reflect.Value
			)

			switch req.Method {
			case http.MethodGet, http.MethodDelete:
				if handlerType.NumIn() != 1 {
					http.Error(w, "handler must have 1 argument", http.StatusInternalServerError)
					return
				}

				in = []reflect.Value{reflect.ValueOf(ctx)}
			default:
				if handlerType.NumIn() != 2 {
					http.Error(w, "handler must have 2 arguments", http.StatusInternalServerError)
					return
				}

				body, err = io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				reqType := handlerType.In(1)
				newReq := reflect.New(reqType).Interface()
				if err := json.Unmarshal(body, newReq); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				in = []reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(newReq).Elem()}
			}

			logger.NewLogger().
				WithContext(ctx).
				With("method", req.Method).
				With("path", req.URL.Path).
				With("body", string(body)).
				With("headers", req.Header).
				With("params", req.URL.Query()).
				Info("Calling handler")

			results := handlerValue.Call(in)
			if len(results) != 2 {
				http.Error(w, "handler must return 2 values", http.StatusInternalServerError)
				return
			}

			resp := results[0].Interface()
			respErr := results[1].Interface()
			if respErr != nil {
				if _err, ok := respErr.(appError.AppError); ok {
					logger.NewLogger().
						WithContext(ctx).
						With("method", req.Method).
						With("path", req.URL.Path).
						With("error", _err.Error()).
						With("stack", string(debug.Stack())).
						Error("Handler error")
					w.WriteHeader(_err.StatusCode())
					json.NewEncoder(w).Encode(&domain.Error{
						Message:   _err.Error(),
						Code:      int(_err.Code()),
						RequestID: common.GetRequestID(ctx),
					})
					return
				}

				if err, ok := respErr.(error); ok {
					logger.NewLogger().
						WithContext(ctx).
						With("method", req.Method).
						With("path", req.URL.Path).
						With("error", err.Error()).
						With("stack", string(debug.Stack())).
						Error("Handler error")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(&domain.Error{
						Message:   err.Error(),
						RequestID: common.GetRequestID(ctx),
					})
					return
				}
			}

			logger.NewLogger().
				WithContext(ctx).
				With("method", req.Method).
				With("path", req.URL.Path).
				With("response", resp).
				Info("Handler response")

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
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
