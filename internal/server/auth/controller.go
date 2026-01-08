package auth

import (
	"nabi-auth/internal/pkg/jwt"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

type IController interface{}

type Controller struct {
	service    IService
	jwtService *jwt.JWTService
	logger     *zap.Logger
}

func NewController(service IService, jwtService *jwt.JWTService, logger *zap.Logger, api fiber.Router) IController {
	c := &Controller{
		service:    service,
		jwtService: jwtService,
		logger:     logger,
	}

	route := api.Group("/auth")

	// Public endpoints (no auth required)
	route.Get("/.well-known/jwks.json", c.getPublicKey) // JWKS endpoint (standard)
	route.Get("/public-key", c.getPublicKey)            // Alternative endpoint

	// Authentication endpoints
	route.Post("/register", c.register)
	route.Post("/login", c.login)
	route.Post("/refresh", c.refreshToken)
	route.Post("/logout", c.logout)

	// OTP endpoints
	route.Post("/otp/send", c.sendOTP)
	route.Post("/otp/verify", c.verifyOTP)

	// OAuth2 endpoints
	route.Get("/oauth2/google", c.initiateGoogleOAuth)
	route.Get("/oauth2/google/callback", c.handleGoogleOAuthCallback)
	route.Post("/google/login", c.loginWithGoogle)

	// Telegram endpoints
	route.Post("/telegram/verify", c.verifyTelegram)

	logger.Info("Auth Controller initialized")

	return c
}

func (c *Controller) register(ctx *fiber.Ctx) error {
	var req RegisterRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Failed to parse request body",
		})
	}

	// Basic validation
	if req.Email == "" && req.PhoneNumber == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Email or phone number is required",
		})
	}

	if req.Password == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Password is required",
		})
	}

	response, err := c.service.Register(ctx.Context(), req)
	if err != nil {
		c.logger.Error("Registration failed", zap.Error(err))
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "registration_failed",
			Message: err.Error(),
		})
	}

	return ctx.JSON(response)
}

func (c *Controller) login(ctx *fiber.Ctx) error {
	var req LoginRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Failed to parse request body",
		})
	}

	response, err := c.service.Login(ctx.Context(), req)
	if err != nil {
		c.logger.Error("Login failed", zap.Error(err))
		return ctx.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "authentication_failed",
			Message: err.Error(),
		})
	}

	return ctx.JSON(response)
}

func (c *Controller) refreshToken(ctx *fiber.Ctx) error {
	var req RefreshTokenRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Failed to parse request body",
		})
	}

	response, err := c.service.RefreshToken(ctx.Context(), req.RefreshToken)
	if err != nil {
		c.logger.Error("Token refresh failed", zap.Error(err))
		return ctx.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "token_refresh_failed",
			Message: err.Error(),
		})
	}

	return ctx.JSON(response)
}

func (c *Controller) logout(ctx *fiber.Ctx) error {
	// Get token from Authorization header
	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Authorization header is required",
		})
	}

	// Extract token (assuming "Bearer <token>" format)
	token := authHeader
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	if err := c.service.Logout(ctx.Context(), token); err != nil {
		c.logger.Error("Logout failed", zap.Error(err))
		return ctx.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "logout_failed",
			Message: err.Error(),
		})
	}

	return ctx.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}

func (c *Controller) sendOTP(ctx *fiber.Ctx) error {
	var req SendOTPRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Failed to parse request body",
		})
	}

	response, err := c.service.SendOTP(ctx.Context(), req)
	if err != nil {
		c.logger.Error("Send OTP failed", zap.Error(err))
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "otp_send_failed",
			Message: err.Error(),
		})
	}

	return ctx.JSON(response)
}

func (c *Controller) verifyOTP(ctx *fiber.Ctx) error {
	var req VerifyOTPRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Failed to parse request body",
		})
	}

	response, err := c.service.VerifyOTP(ctx.Context(), req)
	if err != nil {
		c.logger.Error("OTP verification failed", zap.Error(err))
		return ctx.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "otp_verification_failed",
			Message: err.Error(),
		})
	}

	return ctx.JSON(response)
}

func (c *Controller) initiateGoogleOAuth(ctx *fiber.Ctx) error {
	url, err := c.service.InitiateGoogleOAuth(ctx.Context())
	if err != nil {
		c.logger.Error("Google OAuth initiation failed", zap.Error(err))
		return ctx.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "oauth_initiation_failed",
			Message: err.Error(),
		})
	}

	return ctx.Redirect(url, fiber.StatusTemporaryRedirect)
}

func (c *Controller) handleGoogleOAuthCallback(ctx *fiber.Ctx) error {
	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Authorization code is required",
		})
	}

	response, err := c.service.HandleGoogleOAuthCallback(ctx.Context(), code)
	if err != nil {
		c.logger.Error("Google OAuth callback failed", zap.Error(err))
		return ctx.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "oauth_callback_failed",
			Message: err.Error(),
		})
	}

	return ctx.JSON(response)
}

func (c *Controller) loginWithGoogle(ctx *fiber.Ctx) error {
	var req GoogleLoginRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Failed to parse request body",
		})
	}

	response, err := c.service.LoginWithGoogle(ctx.Context(), req)
	if err != nil {
		c.logger.Error("Google login failed", zap.Error(err))
		return ctx.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "google_login_failed",
			Message: err.Error(),
		})
	}

	return ctx.JSON(response)
}

func (c *Controller) verifyTelegram(ctx *fiber.Ctx) error {
	var req TelegramVerifyRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:   "invalid_request",
			Message: "Failed to parse request body",
		})
	}

	response, err := c.service.VerifyTelegramAuth(ctx.Context(), req)
	if err != nil {
		c.logger.Error("Telegram verification failed", zap.Error(err))
		return ctx.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "telegram_verification_failed",
			Message: err.Error(),
		})
	}

	return ctx.JSON(response)
}

// getPublicKey returns the public key in PEM format for other microservices
// This allows other services to verify JWT tokens without needing the private key
func (c *Controller) getPublicKey(ctx *fiber.Ctx) error {
	publicKeyPEM, err := c.jwtService.GetPublicKeyPEM()
	if err != nil {
		c.logger.Error("Failed to get public key", zap.Error(err))
		return ctx.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to retrieve public key",
		})
	}

	// Return in JWKS format (JSON Web Key Set) - standard format
	return ctx.JSON(fiber.Map{
		"keys": []fiber.Map{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"key": string(publicKeyPEM),
			},
		},
		"public_key_pem": string(publicKeyPEM),
	})
}
