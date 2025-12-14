package middleware

import (
	"github.com/gofiber/fiber/v2"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"time"
)

func NewLoggerMiddleware(app *fiber.App, log *zap.Logger) {
	app.Use(func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		latency := time.Since(start)
		body := c.Body()

		level := zap.InfoLevel
		if err != nil {
			level = zap.ErrorLevel
		}

		log.Log(level, "",
			zap.Error(err),
			zap.String("path", c.Path()),
			zap.String("IP", c.IP()),
			zap.String("userAgent", c.Get("User-Agent")),
			zap.String("method", c.Method()),
			zap.Any("params", c.AllParams()),
			zap.Any("queries", c.Queries()),
			zap.String("body", string(body)),
			zap.Duration("latency", latency),
		)

		return err
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
}

var Module = fx.Options(
	fx.Invoke(NewLoggerMiddleware),
)
