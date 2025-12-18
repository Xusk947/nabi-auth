package auth

import (
	"nabi-auth/internal/pkg/config"
	"nabi-auth/internal/pkg/jwt"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

var Module = fx.Options(
	fx.Provide(
		NewJWTService,
		fx.Annotate(NewRepository, fx.As(new(IRepository))),
		fx.Annotate(NewService, fx.As(new(IService))),
	),
	fx.Invoke(
		NewController,
	),
)

func NewJWTService(cfg *config.Config, logger *zap.Logger) (*jwt.JWTService, error) {
	return jwt.NewJWTService(cfg.Auth.JWTPrivateKeyPath, cfg.Auth.JWTPublicKeyPath, logger)
}

