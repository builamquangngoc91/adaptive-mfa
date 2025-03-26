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
	"adaptive-mfa/pkg/email"
	"adaptive-mfa/pkg/monitor"
	"adaptive-mfa/pkg/sms"
	"adaptive-mfa/repository"
	"adaptive-mfa/server"

	_ "github.com/lib/pq"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	s.Router.Get("/health", func(ctx context.Context, req any) (any, error) {
		return "Health check OK", nil
	})
	s.Router.Use(middleware.PrometheusMiddleware)

	prometheus.MustRegister(monitor.HttpRequestCounter)
	prometheus.MustRegister(monitor.ActiveRequestsGauge)
	prometheus.MustRegister(monitor.LatencyHistogram)
	prometheus.MustRegister(monitor.LatencySummary)
	prometheus.MustRegister(monitor.SMSSendCounter)
	prometheus.MustRegister(monitor.EmailSendCounter)

	s.Router.Get("/metrics", promhttp.Handler())

	emailService := email.NewEmail()
	smsService := sms.NewSMS()
	registerController := controller.NewRegisterController(cache, userRepository)
	loginController := controller.NewLoginController(cfg, cache, userRepository, userMFARepository, emailService, smsService)
	userVerificationController := controller.NewUserVerificationController(cfg, db, cache, userRepository, userMFARepository, emailService, smsService)
	logoutController := controller.NewLogoutController(cache)
	totpController := controller.NewTOTPController(db, userMFARepository, cache)
	hackedController := controller.NewHackedController(cfg, cache)

	v1Group := s.Router.Group("/v1")
	v1Group.Use(middleware.RequestIDMiddleware)
	{
		authGroup := v1Group.Group("/auth")
		authGroup.Post("/verify-totp-code", totpController.VerifyTOTPCode)
		authGroup.Post("/send-login-email-code", loginController.SendLoginEmailCode)
		authGroup.Post("/verify-login-email-code", loginController.VerifyLoginEmailCode)
		authGroup.Post("/send-login-phone-code", loginController.SendLoginPhoneCode)
		authGroup.Post("/verify-login-phone-code", loginController.VerifyLoginPhoneCode)
		authGroup.Post("/register", registerController.Register)
		authGroup.Post("/login", loginController.Login)
		authGroup.Post("/login-with-mfa", loginController.LoginWithMFA)

		v1Group.Get("/hacked/disavow", hackedController.Disavow)

		requiredAuthGroup := v1Group.Group("")
		requiredAuthGroup.Use(middleware.AuthMiddleware(cfg, cache, userRepository))
		{
			requiredAuthGroup.Delete("/logout", logoutController.Logout)
			requiredAuthGroup.Post("/send-email-verification", userVerificationController.SendEmailVerification)
			requiredAuthGroup.Post("/verify-email-verification", userVerificationController.VerifyEmailVerification)
			requiredAuthGroup.Post("/send-phone-verification", userVerificationController.SendPhoneVerification)
			requiredAuthGroup.Post("/verify-phone-verification", userVerificationController.VerifyPhoneVerification)
			requiredAuthGroup.Post("/add-totp-method", totpController.AddTOTPMethod)
			requiredAuthGroup.Delete("/delete-totp-method", totpController.DeleteTOTPMethod)
			requiredAuthGroup.Get("/list-totp-methods", totpController.ListTOTPMethods)
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
