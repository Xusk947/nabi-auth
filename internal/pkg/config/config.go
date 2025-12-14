package config

import (
	"context"
	"github.com/joho/godotenv"
	"github.com/sethvargo/go-envconfig"
	"go.uber.org/fx"
	"sync"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Auth     Auth
	S3       S3
}

type ServerConfig struct {
	Host       string `env:"HOST,default=localhost:8000"`
	Production bool   `env:"PRODUCTION,default=false"`
}

type DatabaseConfig struct {
	DataBaseUrl string `env:"DATABASE_URL,default=postgresql://postgres:postgres@localhost:5432/postgres?sslmode=disable"`
}

type Auth struct {
	JWTSecret string `env:"JWT_SECRET,default=secret"`
}

type S3 struct {
	URL string `env:"S3_URL"`
}

var (
	once sync.Once
)

func NewConfig() *Config {
	var cfg Config

	once.Do(func() {
		_ = godotenv.Load()

		if err := envconfig.Process(context.Background(), &cfg); err != nil {
			panic(err)
		}
	})

	return &cfg
}

var Module = fx.Module(
	"config", fx.Provide(NewConfig),
)
