package config

import (
	"os"
	"strconv"
	"time"

	"adaptive-mfa/pkg/cache"
	"adaptive-mfa/pkg/database"

	"github.com/joho/godotenv"
	_ "github.com/joho/godotenv/autoload"
)

type Config struct {
	Database   *database.DatabaseConfig
	Cache      *cache.CacheConfig
	JwtSecret  string
	DisavowURL string
	Port       int
	Env        string
	TOTP       *TOTPConfig
	RateLimit  *RateLimitConfig
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(os.Getenv("AMFA_PORT"))
	if err != nil {
		port = 8082
	}

	return &Config{
		Database:   LoadDatabaseConfig(),
		Cache:      LoadCacheConfig(),
		JwtSecret:  os.Getenv("AMFA_JWT_SECRET"),
		DisavowURL: os.Getenv("AMFA_DISAVOW_URL"),
		Port:       port,
		Env:        os.Getenv("AMFA_ENV"),
		TOTP:       LoadTOTPConfig(),
		RateLimit:  LoadRateLimitConfig(),
	}, nil
}

func LoadDatabaseConfig() *database.DatabaseConfig {
	maxOpenConns, err := strconv.Atoi(os.Getenv("AMFA_DB_MAX_CONNECTIONS"))
	if err != nil {
		maxOpenConns = 10
	}
	maxIdleConns, err := strconv.Atoi(os.Getenv("AMFA_DB_IDLE_TIMEOUT"))
	if err != nil {
		maxIdleConns = 30000
	}
	connMaxLifetime, err := strconv.Atoi(os.Getenv("AMFA_DB_CONN_MAX_LIFETIME"))
	if err != nil {
		connMaxLifetime = 30000
	}
	cfg := &database.DatabaseConfig{
		Host:            os.Getenv("AMFA_DB_HOST"),
		Port:            os.Getenv("AMFA_DB_PORT"),
		User:            os.Getenv("AMFA_DB_USER"),
		Password:        os.Getenv("AMFA_DB_PASSWORD"),
		DBName:          os.Getenv("AMFA_DB_NAME"),
		Schema:          os.Getenv("AMFA_DB_SCHEMA"),
		SSLMode:         os.Getenv("AMFA_DB_SSL_MODE"),
		MaxOpenConns:    maxOpenConns,
		MaxIdleConns:    maxIdleConns,
		ConnMaxLifetime: time.Duration(connMaxLifetime) * time.Second,
	}
	return cfg
}

func LoadCacheConfig() *cache.CacheConfig {
	db, err := strconv.Atoi(os.Getenv("AMFA_CACHE_DB"))
	if err != nil {
		db = 0
	}
	return &cache.CacheConfig{
		Host: os.Getenv("AMFA_CACHE_HOST"),
		Port: os.Getenv("AMFA_CACHE_PORT"),
		DB:   db,
	}
}

type TOTPConfig struct {
	Issuer     string
	SecretSize uint
}

func LoadTOTPConfig() *TOTPConfig {
	secretSize, err := strconv.Atoi(os.Getenv("AMFA_TOTP_SECRET_SIZE"))
	if err != nil {
		secretSize = 12
	}
	return &TOTPConfig{
		Issuer:     os.Getenv("AMFA_TOTP_ISSUER"),
		SecretSize: uint(secretSize),
	}
}

type RateLimitConfig struct {
	LoginVerificationAttemptsThreshold    int64
	LoginVerificationAttemptsLockDuration time.Duration
	LoginAttemptsThreshold                int64
	LoginAttemptsLockDuration             time.Duration
}

func LoadRateLimitConfig() *RateLimitConfig {
	loginVerificationAttemptsThreshold, err := strconv.ParseInt(os.Getenv("AMFA_LOGIN_VERIFICATION_ATTEMPTS_THRESHOLD"), 10, 64)
	if err != nil {
		loginVerificationAttemptsThreshold = 20
	}
	loginVerificationAttemptsLockDuration, err := strconv.ParseInt(os.Getenv("AMFA_LOGIN_VERIFICATION_ATTEMPTS_LOCK_DURATION"), 10, 64)
	if err != nil {
		loginVerificationAttemptsLockDuration = 86400
	}
	loginAttemptsThreshold, err := strconv.ParseInt(os.Getenv("AMFA_LOGIN_ATTEMPTS_THRESHOLD"), 10, 64)
	if err != nil {
		loginAttemptsThreshold = 5
	}
	loginAttemptsLockDuration, err := strconv.ParseInt(os.Getenv("AMFA_LOGIN_ATTEMPTS_LOCK_DURATION"), 10, 64)
	if err != nil {
		loginAttemptsLockDuration = 86400
	}
	return &RateLimitConfig{
		LoginVerificationAttemptsThreshold:    loginVerificationAttemptsThreshold,
		LoginVerificationAttemptsLockDuration: time.Duration(loginVerificationAttemptsLockDuration) * time.Second,
		LoginAttemptsThreshold:                loginAttemptsThreshold,
		LoginAttemptsLockDuration:             time.Duration(loginAttemptsLockDuration) * time.Second,
	}
}
