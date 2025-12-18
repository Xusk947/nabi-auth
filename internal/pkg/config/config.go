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
}

type ServerConfig struct {
	Host       string `env:"HOST,default=localhost:8000"`
	Production bool   `env:"PRODUCTION,default=false"`
}

type DatabaseConfig struct {
	DataBaseUrl string `env:"DATABASE_URL,default=postgresql://postgres:postgres@localhost:5432/postgres?sslmode=disable"`
}

type Auth struct {
	JWTPrivateKeyPath   string `env:"JWT_PRIVATE_KEY_PATH,default=./keys/jwt_private.pem"`
	JWTPublicKeyPath    string `env:"JWT_PUBLIC_KEY_PATH,default=./keys/jwt_public.pem"`
	AccessTokenTTL      int    `env:"ACCESS_TOKEN_TTL,default=3600"`      // 1 hour in seconds
	RefreshTokenTTL     int    `env:"REFRESH_TOKEN_TTL,default=2592000"`  // 30 days in seconds
	GoogleClientID      string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret  string `env:"GOOGLE_CLIENT_SECRET"`
	GoogleRedirectURL   string `env:"GOOGLE_REDIRECT_URL,default=http://localhost:8000/auth/oauth2/google/callback"`
	TelegramBotToken    string `env:"TELEGRAM_BOT_TOKEN"`
	OTPExpiration       int    `env:"OTP_EXPIRATION,default=600"` // 10 minutes in seconds
	OTPMaxAttempts      int    `env:"OTP_MAX_ATTEMPTS,default=5"`
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
