package example

import (
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

type IController interface{}

type Controller struct {
	Service IService
}

func NewController(service IService, log *zap.Logger, api fiber.Router) IController {
	c := &Controller{Service: service}

	route := api.Group("/example")

	route.Get("/tables", c.getTables)

	log.Info("Example Controller initialized")

	return c
}

func (c *Controller) getTables(ctx *fiber.Ctx) error {
	tables, err := c.Service.GetTables(ctx.Context())
	if err != nil {
		return err
	}
	return ctx.JSON(tables)
}
