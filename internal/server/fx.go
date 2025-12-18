package server

import (
	"nabi-auth/internal/server/auth"
	"go.uber.org/fx"
)

var Module = fx.Options(
	auth.Module,
)
