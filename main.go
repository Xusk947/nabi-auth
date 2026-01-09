package main

import (
	"nabi-auth/internal/pkg"
	"nabi-auth/internal/server"

	"go.uber.org/fx"

	_ "nabi-auth/docs"
)

// @title           Nabi Auth API
// @version         latest
// @description     Сервис аунтефикации отвечает за регистрацию логин и oauth otp и прочие методы включая выдачу JWT токена
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.email  support@example.com

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:3000
// @BasePath  /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	fx.New(fx.Options(pkg.Module, server.Module)).Run()
}
