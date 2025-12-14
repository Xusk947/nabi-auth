package logger

import (
	"fiber-di-server-template/internal/pkg/config"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

var Log *zap.Logger

func NewLogger(cfg *config.Config) *zap.Logger {
	if cfg.Server.Production {
		prod, err := zap.NewProduction()
		if err != nil {
			panic(err)
		}
		Log = prod
		return prod
	} else {
		dev, err := zap.NewDevelopment()
		if err != nil {
			panic(err)
		}
		Log = dev
		return dev
	}
}

var Module = fx.Options(
	fx.Provide(NewLogger),
)
