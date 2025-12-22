package server

import (
	"go.uber.org/fx"
	"nabi-auth/internal/server/auth"
)

var Module = fx.Options(
	auth.Module,
)
