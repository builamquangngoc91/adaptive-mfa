package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"adaptive-mfa/config"
	"adaptive-mfa/handlers"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/database"
	"adaptive-mfa/repositories"

	_ "github.com/lib/pq"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := database.NewDatabase(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	if err := db.Ping(context.Background()); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	fmt.Println("Connected to database")

	cache, err := cache.New(cfg.Cache)
	if err != nil {
		log.Fatalf("Failed to connect to cache: %v", err)
	}

	if err := cache.Ping(context.Background()); err != nil {
		log.Fatalf("Failed to ping cache: %v", err)
	}
	fmt.Println("Connected to cache")

	userRepository := repositories.NewUserRepository(db)

	router := http.ServeMux{}
	// Register routes with methods
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Health check OK"))
	})

	authHandler := handlers.NewAuthHandler(cache, userRepository)
	router.HandleFunc("/v1/register", authHandler.Register)
	router.HandleFunc("/v1/login", authHandler.Login)
	router.HandleFunc("/v1/logout", authHandler.Logout)
	router.HandleFunc("/v1/send-email-verification", authHandler.SendEmailVerification)
	router.HandleFunc("/v1/verify-email-verification", authHandler.VerifyEmailVerification)
	router.HandleFunc("/v1/send-phone-verification", authHandler.SendPhoneVerification)
	router.HandleFunc("/v1/verify-phone-verification", authHandler.VerifyPhoneVerification)

	// Server configuration
	port := 8082
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      &router,
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
