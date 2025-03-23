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
	Database *database.DatabaseConfig
	Cache    *cache.CacheConfig
	Jwt      string
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, err
	}

	return &Config{
		Database: LoadDatabaseConfig(),
		Cache:    LoadCacheConfig(),
		Jwt:      os.Getenv("AMFA_JWT_SECRET"),
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
