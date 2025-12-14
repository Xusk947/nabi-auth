package main

import (
	"fiber-di-server-template/internal/pkg"
	"fiber-di-server-template/internal/server"
	"go.uber.org/fx"
)

func main() {
	fx.New(fx.Options(pkg.Module, server.Module)).Run()
}
