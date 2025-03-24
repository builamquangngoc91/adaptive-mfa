package main

import (
	"context"
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
	cache, err := cache.New(cfg.Cache)
	if err != nil {
		log.Fatalf("Failed to connect to cache: %v", err)
	}

	userRepository := repository.NewUserRepository(db)
	userMFARepository := repository.NewUserMFARepository(db)

	s := server.NewServer(8082)
	s.Router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Health check OK"))
	})

	registerController := controller.NewRegisterController(cache, userRepository)
	loginController := controller.NewLoginController(cfg, cache, userRepository, userMFARepository)
	userVerificationController := controller.NewUserVerificationController(cfg, db, cache, userRepository, userMFARepository)
	logoutController := controller.NewLogoutController(cache)
	totpController := controller.NewTOTPController(db, userMFARepository, cache)

	v1Group := s.Router.Group("/v1")
	v1Group.Use(middleware.LoggerMiddleware)

	{
		v1Group.Post("/register", registerController.Register)
		v1Group.Post("/login", loginController.Login)

		requiredAuthGroup := v1Group.Group("")
		requiredAuthGroup.Use(middleware.AuthMiddleware(cfg, cache, userRepository))
		{
			requiredAuthGroup.Delete("/logout", logoutController.Logout)
			requiredAuthGroup.Post("/send-email-verification", userVerificationController.SendEmailVerification)
			requiredAuthGroup.Post("/verify-email-verification", userVerificationController.VerifyEmailVerification)
			requiredAuthGroup.Post("/send-phone-verification", userVerificationController.SendPhoneVerification)
			requiredAuthGroup.Post("/verify-phone-verification", userVerificationController.VerifyPhoneVerification)
			requiredAuthGroup.Get("/add-totp-method", totpController.AddTOTPMethod)
			requiredAuthGroup.Delete("/delete-totp-method", totpController.DeleteTOTPMethod)
			requiredAuthGroup.Get("/list-totp-methods", totpController.ListTOTPMethods)
		}

		v1Group.Post("/verify-totp-code", totpController.VerifyTOTPCode)
		v1Group.Post("/send-login-email-code", loginController.SendLoginEmailCode)
		v1Group.Post("/verify-login-email-code", loginController.VerifyLoginEmailCode)
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
