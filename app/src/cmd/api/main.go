package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Router is a custom HTTP router that handles different methods for the same path
type Router struct {
	routes map[string]map[string]http.HandlerFunc
}

// NewRouter creates a new router instance
func NewRouter() *Router {
	return &Router{
		routes: make(map[string]map[string]http.HandlerFunc),
	}
}

// Handle registers a handler for a specific path and method
func (r *Router) Handle(method, path string, handler http.HandlerFunc) {
	if r.routes[path] == nil {
		r.routes[path] = make(map[string]http.HandlerFunc)
	}
	r.routes[path][method] = handler
}

// GET registers a handler for the GET method
func (r *Router) GET(path string, handler http.HandlerFunc) {
	r.Handle(http.MethodGet, path, handler)
}

// POST registers a handler for the POST method
func (r *Router) POST(path string, handler http.HandlerFunc) {
	r.Handle(http.MethodPost, path, handler)
}

// PUT registers a handler for the PUT method
func (r *Router) PUT(path string, handler http.HandlerFunc) {
	r.Handle(http.MethodPut, path, handler)
}

// DELETE registers a handler for the DELETE method
func (r *Router) DELETE(path string, handler http.HandlerFunc) {
	r.Handle(http.MethodDelete, path, handler)
}

// ServeHTTP implements the http.Handler interface
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Get the handlers for this path
	if handlers, ok := r.routes[req.URL.Path]; ok {
		// Check if we have a handler for this method
		if handler, ok := handlers[req.Method]; ok {
			handler(w, req)
			return
		}
		// Method not allowed
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "Method %s not allowed for path %s", req.Method, req.URL.Path)
		return
	}

	// No route matched - 404
	http.NotFound(w, req)
}

// Handler that responds to GET requests on the root path
func getRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the simple Go server!")
}

// Handler that responds to GET requests on the /api/hello endpoint
func getHello(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"message": "Hello, World!",
		"time":    time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Handler that responds to POST requests on the /api/echo endpoint
func postEcho(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
}

// Custom logger middleware
func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Request started: %s %s", r.Method, r.URL.Path)

		next.ServeHTTP(w, r)

		log.Printf("Request completed: %s %s in %v", r.Method, r.URL.Path, time.Since(start))
	})
}

func main() {
	// Create a new router
	router := NewRouter()

	// Register handlers for different paths and methods
	router.GET("/", getRoot)
	router.GET("/api/hello", getHello)
	router.POST("/api/echo", postEcho)

	// Apply the logger middleware
	handler := loggerMiddleware(router)

	// Server configuration
	port := 8082
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to listen for interrupt signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Start the server in a goroutine
	go func() {
		log.Printf("Server starting on port %d...", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-stop
	log.Println("Shutdown signal received, gracefully shutting down...")

	// Create a deadline context for the shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server gracefully stopped")
}
