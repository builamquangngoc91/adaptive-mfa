package server

import "net/http"

type RouterGroup struct {
	prefix      string
	router      *Router
	basePath    string
	middlewares []Middleware
}

func (r *RouterGroup) Group(prefix string) *RouterGroup {
	return &RouterGroup{
		prefix:      prefix,
		router:      r.router,
		basePath:    r.basePath + r.prefix,
		middlewares: r.middlewares,
	}
}

func (g *RouterGroup) Use(middleware Middleware) {
	g.middlewares = append(g.middlewares, middleware)
}

func (g *RouterGroup) Get(path string, handler Handler) {
	g.router.addRoute(http.MethodGet, g.getFullPath(path), handler, g.middlewares...)
}

func (g *RouterGroup) Post(path string, handler Handler) {
	g.router.addRoute(http.MethodPost, g.getFullPath(path), handler, g.middlewares...)
}

func (g *RouterGroup) Put(path string, handler Handler) {
	g.router.addRoute(http.MethodPut, g.getFullPath(path), handler, g.middlewares...)
}

func (g *RouterGroup) Delete(path string, handler Handler) {
	g.router.addRoute(http.MethodDelete, g.getFullPath(path), handler, g.middlewares...)
}

func (g *RouterGroup) getFullPath(path string) string {
	return g.basePath + g.prefix + path
}
