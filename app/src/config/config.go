package config

import (
	"os"

	"github.com/joho/godotenv"
	_ "github.com/joho/godotenv/autoload"
)

type Config struct {
	Database *DatabaseConfig
}

type DatabaseConfig struct {
	Host     string `env:"POSTGRES_HOST"`
	Port     string `env:"POSTGRES_PORT"`
	User     string `env:"POSTGRES_USER"`
	Password string `env:"POSTGRES_PASSWORD"`
	DBName   string `env:"POSTGRES_DB"`
	Schema   string `env:"POSTGRES_SCHEMA"`
	SSLMode  string `env:"POSTGRES_SSL_MODE"`
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, err
	}

	return &Config{
		Database: LoadDatabaseConfig(),
	}, nil
}

func LoadDatabaseConfig() *DatabaseConfig {
	cfg := &DatabaseConfig{
		Host:     os.Getenv("POSTGRES_HOST"),
		Port:     os.Getenv("POSTGRES_PORT"),
		User:     os.Getenv("POSTGRES_USER"),
		Password: os.Getenv("POSTGRES_PASSWORD"),
		DBName:   os.Getenv("POSTGRES_DB"),
		Schema:   os.Getenv("POSTGRES_SCHEMA"),
		SSLMode:  os.Getenv("POSTGRES_SSL_MODE"),
	}
	return cfg
}
