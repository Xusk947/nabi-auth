package server

import (
	"context"
	"fiber-di-server-template/internal/pkg/config"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

func NewFiberApp() *fiber.App {
	app := fiber.New(fiber.Config{
		ServerHeader:          "Securifi",
		DisableStartupMessage: true,
	})

	return app
}

func RunFiberApp(lc fx.Lifecycle, app *fiber.App, log *zap.Logger, cfg *config.Config) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			go func() {
				log.Named("Server").Info(fmt.Sprintf("Listening on address %s", cfg.Server.Host))
				if err := app.Listen(cfg.Server.Host); err != nil {
					log.Named("Server").Error("Server failed to start", zap.Error(err))
				}
			}()

			return nil
		},
		OnStop: func(ctx context.Context) error {
			log.Info("Grace fully shutdown Server")
			return app.Shutdown()
		},
	})
}
func ExportApiRoute(app *fiber.App) fiber.Router {
	return app.Group("/")
}

var Module = fx.Options(
	fx.Provide(NewFiberApp),
	fx.Provide(ExportApiRoute),
	fx.Invoke(RunFiberApp),
)
