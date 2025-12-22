package pkg

import (
	"nabi-auth/internal/pkg/config"
	"nabi-auth/internal/pkg/database"
	"nabi-auth/internal/pkg/grpc"
	"nabi-auth/internal/pkg/jwt"
	"nabi-auth/internal/pkg/logger"
	"nabi-auth/internal/pkg/middleware"
	"nabi-auth/internal/pkg/server"

	"go.uber.org/fx"
)

var Module = fx.Options(
	config.Module,
	logger.Module,
	database.Module,
	jwt.Module,
	grpc.Module,
	server.Module,
	middleware.Module,
)
