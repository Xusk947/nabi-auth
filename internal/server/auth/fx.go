package auth

import (
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(
		fx.Annotate(NewRepository, fx.As(new(IRepository))),
		fx.Annotate(NewService, fx.As(new(IService))),
	),
	fx.Invoke(
		NewController,
	),
)
