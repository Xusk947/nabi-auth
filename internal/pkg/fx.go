package pkg

import (
	"nabi-auth/internal/pkg/config"
	"nabi-auth/internal/pkg/database"
	"nabi-auth/internal/pkg/logger"
	"nabi-auth/internal/pkg/middleware"
	"nabi-auth/internal/pkg/server"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
)

var Module = fx.Options(
	config.Module,
	logger.Module,
	fx.WithLogger(func(log *zap.Logger, cfg *config.Config) fxevent.Logger {
		if cfg.Server.Production {
			return &fxevent.ZapLogger{Logger: log.Named("fx").WithOptions(zap.IncreaseLevel(zap.ErrorLevel))}
		}
		return &fxevent.ZapLogger{Logger: log.Named("fx")}
	}),
	database.Module,
	server.Module,
	middleware.Module,
)
