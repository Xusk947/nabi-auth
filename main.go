package main

import (
	"nabi-auth/internal/pkg"
	"nabi-auth/internal/server"
	"go.uber.org/fx"
)

func main() {
	fx.New(fx.Options(pkg.Module, server.Module)).Run()
}
