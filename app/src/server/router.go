package server

import (
	"fmt"
	"net/http"
	"strings"
)

type Handler func(w http.ResponseWriter, r *http.Request)

type HandlerWithMiddlewares struct {
	Handler     Handler
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

func (r *Router) addRoute(method, path string, handler Handler, middlewares ...Middleware) {
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

func (r *Router) Get(path string, handler Handler) {
	r.addRoute(http.MethodGet, path, handler)
}

func (r *Router) Post(path string, handler Handler) {
	r.addRoute(http.MethodPost, path, handler)
}

func (r *Router) Put(path string, handler Handler) {
	r.addRoute(http.MethodPut, path, handler)
}

func (r *Router) Delete(path string, handler Handler) {
	r.addRoute(http.MethodDelete, path, handler)
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	handlerWithMiddlewares, err := r.findHandlerWithMiddlewares(req.Method, req.URL.Path)
	if err != nil {
		r.notFoundHandler(w, req)
		return
	}
	Chain(handlerWithMiddlewares.Handler, handlerWithMiddlewares.Middlewares...)(w, req)
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
