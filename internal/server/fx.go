package server

import (
	"fiber-di-server-template/internal/server/example"
	"go.uber.org/fx"
)

var Module = fx.Options(
	example.Module,
)
