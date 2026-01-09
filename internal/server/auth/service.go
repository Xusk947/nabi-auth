package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"

	db "nabi-auth/db/gen/queries.go"
	"nabi-auth/internal/pkg/config"
	"nabi-auth/internal/pkg/jwt"

	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type IService interface {
	Register(ctx context.Context, req RegisterRequest) (*AuthResponse, error)
	Login(ctx context.Context, req LoginRequest) (*AuthResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error)
	Logout(ctx context.Context, token string) error

	SendOTP(ctx context.Context, req SendOTPRequest) (*OTPResponse, error)
	VerifyOTP(ctx context.Context, req VerifyOTPRequest) (*AuthResponse, error)

	LoginWithGoogle(ctx context.Context, req GoogleLoginRequest) (*AuthResponse, error)

	InitiateGoogleOAuth(ctx context.Context) (string, error)
	HandleGoogleOAuthCallback(ctx context.Context, code string) (*AuthResponse, error)

	VerifyTelegramAuth(ctx context.Context, req TelegramVerifyRequest) (*AuthResponse, error)
}

type Service struct {
	repository  IRepository
	jwtService  *jwt.JWTService
	config      *config.Config
	logger      *zap.Logger
	googleOAuth *oauth2.Config
}

func NewService(repository IRepository, jwtService *jwt.JWTService, cfg *config.Config, logger *zap.Logger) IService {
	googleOAuth := &oauth2.Config{
		ClientID:     cfg.Auth.GoogleClientID,
		ClientSecret: cfg.Auth.GoogleClientSecret,
		RedirectURL:  cfg.Auth.GoogleRedirectURL,
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     google.Endpoint,
	}

	return &Service{
		repository:  repository,
		jwtService:  jwtService,
		config:      cfg,
		logger:      logger,
		googleOAuth: googleOAuth,
	}
}

// Register creates a new user with password authentication
func (s *Service) Register(ctx context.Context, req RegisterRequest) (*AuthResponse, error) {
	// Check if user already exists
	var user db.User
	var err error

	if req.Email != "" {
		user, err = s.repository.GetUserByEmail(ctx, req.Email)
		if err == nil {
			return nil, errors.New("user with this email already exists")
		}
	}

	// Generate password hash
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	var emailPg, phonePg pgtype.Text
	if req.Email != "" {
		emailPg.Scan(req.Email)
	}
	if req.PhoneNumber != "" {
		phonePg.Scan(req.PhoneNumber)
	}

	user, err = s.repository.CreateUser(ctx, emailPg, phonePg, pgtype.Text{}, pgtype.Int8{}, pgtype.Text{})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Create password auth method
	passwordData := PasswordAuthData{
		PasswordHash: string(passwordHash),
	}
	_, err = s.repository.CreateAuthMethod(ctx, user.ID, db.AuthMethodTypePassword, passwordData)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth method: %w", err)
	}

	// Generate tokens
	return s.generateAuthResponse(ctx, user)
}

// Login authenticates a user with email/phone and password
func (s *Service) Login(ctx context.Context, req LoginRequest) (*AuthResponse, error) {
	// Get user by email
	user, err := s.repository.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Get password auth method
	authMethod, err := s.repository.GetAuthMethodByUserIDAndType(ctx, user.ID, db.AuthMethodTypePassword)
	if err != nil {
		return nil, errors.New("password authentication not set up for this user")
	}

	// Verify password
	var passwordData PasswordAuthData
	if err := json.Unmarshal(authMethod.MethodData, &passwordData); err != nil {
		return nil, fmt.Errorf("failed to parse auth method data: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordData.PasswordHash), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Generate tokens
	return s.generateAuthResponse(ctx, user)
}

// RefreshToken refreshes an access token using a refresh token
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	// Validate refresh token
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Check if session exists
	_, err = s.repository.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.New("session not found")
	}

	// Get user
	user, err := s.repository.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate new tokens
	return s.generateAuthResponse(ctx, user)
}

// Logout invalidates a session
func (s *Service) Logout(ctx context.Context, token string) error {
	return s.repository.DeleteSessionByToken(ctx, token)
}

// SendOTP generates and sends an OTP code
func (s *Service) SendOTP(ctx context.Context, req SendOTPRequest) (*OTPResponse, error) {
	// Find or create user
	var user db.User
	var err error

	if strings.Contains(req.Identifier, "@") {
		user, err = s.repository.GetUserByEmail(ctx, req.Identifier)
	} else {
		user, err = s.repository.GetUserByPhone(ctx, req.Identifier)
	}

	if err != nil {
		// Create new user if doesn't exist
		var emailPg, phonePg pgtype.Text
		if strings.Contains(req.Identifier, "@") {
			emailPg.Scan(req.Identifier)
		} else {
			phonePg.Scan(req.Identifier)
		}

		user, err = s.repository.CreateUser(ctx, emailPg, phonePg, pgtype.Text{}, pgtype.Int8{}, pgtype.Text{})
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	// Generate OTP code
	code := generateOTPCode(6)
	codeHash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash OTP code: %w", err)
	}

	// Create OTP record
	expiresAt := time.Now().Add(time.Duration(s.config.Auth.OTPExpiration) * time.Second)
	var expiresAtPg pgtype.Timestamp
	expiresAtPg.Scan(expiresAt)

	_, err = s.repository.CreateOTPCode(ctx, user.ID, req.Identifier, string(codeHash), expiresAtPg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTP code: %w", err)
	}

	// TODO: Send OTP via email/SMS service
	s.logger.Info("OTP code generated", zap.String("identifier", req.Identifier), zap.String("code", code))

	return &OTPResponse{
		Message:   "OTP code sent successfully",
		ExpiresIn: s.config.Auth.OTPExpiration,
	}, nil
}

// VerifyOTP verifies an OTP code and authenticates the user
func (s *Service) VerifyOTP(ctx context.Context, req VerifyOTPRequest) (*AuthResponse, error) {
	// Get OTP code
	otpCode, err := s.repository.GetOTPCodeByIdentifier(ctx, req.Identifier)
	if err != nil {
		return nil, errors.New("invalid or expired OTP code")
	}

	// Check attempts
	if otpCode.Attempts >= int32(s.config.Auth.OTPMaxAttempts) {
		return nil, errors.New("maximum OTP attempts exceeded")
	}

	// Verify code
	if err := bcrypt.CompareHashAndPassword([]byte(otpCode.CodeHash), []byte(req.Code)); err != nil {
		_ = s.repository.IncrementOTPAttempts(ctx, otpCode.ID)
		return nil, errors.New("invalid OTP code")
	}

	// Mark OTP as used
	if err := s.repository.MarkOTPAsUsed(ctx, otpCode.ID); err != nil {
		return nil, fmt.Errorf("failed to mark OTP as used: %w", err)
	}

	// Get user
	user, err := s.repository.GetUserByID(ctx, otpCode.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Create or update OTP auth method
	_, err = s.repository.GetAuthMethodByUserIDAndType(ctx, user.ID, db.AuthMethodTypeOtp)
	if err != nil {
		// Create OTP auth method
		_, err = s.repository.CreateAuthMethod(ctx, user.ID, db.AuthMethodTypeOtp, map[string]interface{}{})
		if err != nil {
			s.logger.Warn("Failed to create OTP auth method", zap.Error(err))
		}
	}

	// Generate tokens
	return s.generateAuthResponse(ctx, user)
}

// LoginWithGoogle authenticates a user using Google profile data provided by frontend
func (s *Service) LoginWithGoogle(ctx context.Context, req GoogleLoginRequest) (*AuthResponse, error) {
	// Find or create user
	user, err := s.repository.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Create new user
		var emailPg pgtype.Text
		emailPg.Scan(req.Email)

		var avatarPg pgtype.Text
		if req.AvatarURL != "" {
			avatarPg.Scan(req.AvatarURL)
		}

		user, err = s.repository.CreateUser(ctx, emailPg, pgtype.Text{}, pgtype.Text{}, pgtype.Int8{}, avatarPg)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	// Create or update Google auth method
	googleData := GoogleAuthData{
		GoogleID: req.ExternalID,
		Email:    req.Email,
	}

	authMethod, err := s.repository.GetAuthMethodByUserIDAndType(ctx, user.ID, db.AuthMethodTypeGoogle)
	if err != nil {
		// Create new auth method
		_, err = s.repository.CreateAuthMethod(ctx, user.ID, db.AuthMethodTypeGoogle, googleData)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth method: %w", err)
		}
	} else {
		// Update existing auth method
		_, err = s.repository.UpdateAuthMethod(ctx, authMethod.ID, googleData, true)
		if err != nil {
			return nil, fmt.Errorf("failed to update auth method: %w", err)
		}
	}

	// Generate tokens
	return s.generateAuthResponse(ctx, user)
}

// InitiateGoogleOAuth initiates Google OAuth2 flow
func (s *Service) InitiateGoogleOAuth(ctx context.Context) (string, error) {
	if s.config.Auth.GoogleClientID == "" || s.config.Auth.GoogleClientSecret == "" {
		return "", errors.New("Google OAuth2 not configured")
	}

	state := generateRandomString(32)
	url := s.googleOAuth.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return url, nil
}

// HandleGoogleOAuthCallback handles Google OAuth2 callback
func (s *Service) HandleGoogleOAuthCallback(ctx context.Context, code string) (*AuthResponse, error) {
	if s.config.Auth.GoogleClientID == "" || s.config.Auth.GoogleClientSecret == "" {
		return nil, errors.New("Google OAuth2 not configured")
	}

	// Exchange code for token
	token, err := s.googleOAuth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	// Get user info from Google
	client := s.googleOAuth.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var googleUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Find or create user
	user, err := s.repository.GetUserByEmail(ctx, googleUser.Email)
	if err != nil {
		// Create new user
		var emailPg pgtype.Text
		emailPg.Scan(googleUser.Email)

		var avatarPg pgtype.Text
		if googleUser.Picture != "" {
			avatarPg.Scan(googleUser.Picture)
		}

		user, err = s.repository.CreateUser(ctx, emailPg, pgtype.Text{}, pgtype.Text{}, pgtype.Int8{}, avatarPg)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	// Create or update Google auth method
	googleData := GoogleAuthData{
		GoogleID:     googleUser.ID,
		Email:        googleUser.Email,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	authMethod, err := s.repository.GetAuthMethodByUserIDAndType(ctx, user.ID, db.AuthMethodTypeGoogle)
	if err != nil {
		// Create new auth method
		_, err = s.repository.CreateAuthMethod(ctx, user.ID, db.AuthMethodTypeGoogle, googleData)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth method: %w", err)
		}
	} else {
		// Update existing auth method
		_, err = s.repository.UpdateAuthMethod(ctx, authMethod.ID, googleData, true)
		if err != nil {
			return nil, fmt.Errorf("failed to update auth method: %w", err)
		}
	}

	// Generate tokens
	return s.generateAuthResponse(ctx, user)
}

// VerifyTelegramAuth verifies Telegram WebApp authentication
func (s *Service) VerifyTelegramAuth(ctx context.Context, req TelegramVerifyRequest) (*AuthResponse, error) {
	if s.config.Auth.TelegramBotToken == "" {
		return nil, errors.New("Telegram bot token not configured")
	}

	// Parse initData
	initData, err := url.ParseQuery(req.InitData)
	if err != nil {
		return nil, errors.New("invalid init data format")
	}

	// Extract data
	hash := initData.Get("hash")
	authDateStr := initData.Get("auth_date")
	authDate, err := strconv.ParseInt(authDateStr, 10, 64)
	if err != nil {
		return nil, errors.New("invalid auth date")
	}

	// Check if auth is not too old (24 hours)
	if time.Now().Unix()-authDate > 86400 {
		return nil, errors.New("authentication data expired")
	}

	// Verify hash
	dataCheckString := buildDataCheckString(initData, "hash")
	secretKey := hmacSHA256([]byte(s.config.Auth.TelegramBotToken), "WebAppData")
	calculatedHash := hex.EncodeToString(hmacSHA256(secretKey, dataCheckString))

	if calculatedHash != hash {
		return nil, errors.New("invalid hash")
	}

	// Extract user data
	userStr := initData.Get("user")
	if userStr == "" {
		return nil, errors.New("user data not found")
	}

	var telegramUser struct {
		ID        int64  `json:"id"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name,omitempty"`
		Username  string `json:"username,omitempty"`
		PhotoURL  string `json:"photo_url,omitempty"`
	}

	if err := json.Unmarshal([]byte(userStr), &telegramUser); err != nil {
		return nil, fmt.Errorf("failed to parse user data: %w", err)
	}

	// Find or create user
	user, err := s.repository.GetUserByTelegramID(ctx, telegramUser.ID)
	if err != nil {
		// Create new user
		var telegramUsernamePg pgtype.Text
		if telegramUser.Username != "" {
			telegramUsernamePg.Scan(telegramUser.Username)
		}

		var telegramIDPg pgtype.Int8
		telegramIDPg.Scan(telegramUser.ID)

		var avatarPg pgtype.Text
		if telegramUser.PhotoURL != "" {
			avatarPg.Scan(telegramUser.PhotoURL)
		}

		user, err = s.repository.CreateUser(ctx, pgtype.Text{}, pgtype.Text{}, telegramUsernamePg, telegramIDPg, avatarPg)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	// Create or update Telegram auth method
	telegramData := TelegramAuthData{
		TelegramID: telegramUser.ID,
		Username:   telegramUser.Username,
		FirstName:  telegramUser.FirstName,
		LastName:   telegramUser.LastName,
		PhotoURL:   telegramUser.PhotoURL,
		AuthDate:   authDate,
		Hash:       hash,
	}

	authMethod, err := s.repository.GetAuthMethodByUserIDAndType(ctx, user.ID, db.AuthMethodTypeTelegram)
	if err != nil {
		// Create new auth method
		_, err = s.repository.CreateAuthMethod(ctx, user.ID, db.AuthMethodTypeTelegram, telegramData)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth method: %w", err)
		}
	} else {
		// Update existing auth method
		_, err = s.repository.UpdateAuthMethod(ctx, authMethod.ID, telegramData, true)
		if err != nil {
			return nil, fmt.Errorf("failed to update auth method: %w", err)
		}
	}

	// Generate tokens
	return s.generateAuthResponse(ctx, user)
}

// Helper functions

func (s *Service) generateAuthResponse(ctx context.Context, user db.User) (*AuthResponse, error) {
	// Generate tokens
	accessTokenTTL := time.Duration(s.config.Auth.AccessTokenTTL) * time.Second
	refreshTokenTTL := time.Duration(s.config.Auth.RefreshTokenTTL) * time.Second

	tokenPair, err := s.jwtService.GenerateTokenPair(user.ID, accessTokenTTL, refreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Create session
	expiresAt := time.Now().Add(refreshTokenTTL)
	var expiresAtPg pgtype.Timestamp
	expiresAtPg.Scan(expiresAt)

	_, err = s.repository.CreateSession(ctx, user.ID, tokenPair.AccessToken, tokenPair.RefreshToken, expiresAtPg)
	if err != nil {
		s.logger.Warn("Failed to create session", zap.Error(err))
	}

	return &AuthResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
		User:         ToUserInfo(user.ID, user.Email, user.PhoneNumber, user.TelegramUsername, user.AvatarUrl),
	}, nil
}

func generateOTPCode(length int) string {
	rand.Seed(time.Now().UnixNano())
	code := ""
	for i := 0; i < length; i++ {
		code += strconv.Itoa(rand.Intn(10))
	}
	return code
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func buildDataCheckString(data url.Values, excludeKey string) string {
	var parts []string
	for key, values := range data {
		if key != excludeKey {
			parts = append(parts, fmt.Sprintf("%s=%s", key, values[0]))
		}
	}
	return strings.Join(parts, "\n")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
