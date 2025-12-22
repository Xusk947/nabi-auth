package main

import (
	"go.uber.org/fx"
	"nabi-auth/internal/pkg"
	"nabi-auth/internal/server"
)

func main() {
	fx.New(fx.Options(pkg.Module, server.Module)).Run()
}
