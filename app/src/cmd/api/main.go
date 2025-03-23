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
	"adaptive-mfa/controller"
	"adaptive-mfa/middleware"
	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/database"
	"adaptive-mfa/repository"
	"adaptive-mfa/server"

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

	userRepository := repository.NewUserRepository(db)

	s := server.NewServer(8082)

	s.Router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Health check OK"))
	})

	authHandler := controller.NewAuthHandler(cache, userRepository)

	v1Group := s.Router.Group("/v1")
	v1Group.Use(middleware.LoggerMiddleware)

	{
		v1Group.Post("/register", authHandler.Register)
		v1Group.Post("/login", authHandler.Login)

		requiredAuthGroup := v1Group.Group("")
		requiredAuthGroup.Use(middleware.AuthMiddleware(userRepository, cache))
		{
			requiredAuthGroup.Delete("/logout", authHandler.Logout)
			requiredAuthGroup.Post("/send-email-verification", authHandler.SendEmailVerification)
			requiredAuthGroup.Post("/verify-email-verification", authHandler.VerifyEmailVerification)
			requiredAuthGroup.Post("/send-phone-verification", authHandler.SendPhoneVerification)
			requiredAuthGroup.Post("/verify-phone-verification", authHandler.VerifyPhoneVerification)
		}
	}

	// Channel to listen for interrupt signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Start the server in a goroutine
	go func() {
		log.Printf("Server starting on port %d...", 8082)
		if err := s.Run(); err != nil && err != http.ErrServerClosed {
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
	if err := s.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server gracefully stopped")
}
