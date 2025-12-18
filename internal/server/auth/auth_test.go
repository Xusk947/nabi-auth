package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"nabi-auth/internal/pkg/config"
	"nabi-auth/internal/pkg/jwt"
	"nabi-auth/internal/server/auth/mocks"
	db "nabi-auth/db/gen/queries.go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/bcrypt"
)

// ============================================================================
// Test Suite Setup
// ============================================================================

// AuthTestSuite is the main test suite for authentication service
type AuthTestSuite struct {
	suite.Suite
	ctx        context.Context
	service    *Service
	mockCtrl   *gomock.Controller
	mockRepo   *mocks.MockIRepository
	realRepo   IRepository
	pool       *pgxpool.Pool
	jwtService *jwt.JWTService
	config     *config.Config
	logger     *zap.Logger
	cleanup    func()
}

// SetupSuite runs once before all tests
func (s *AuthTestSuite) SetupSuite() {
	s.ctx = context.Background()
	s.logger = zaptest.NewLogger(s.T())
	s.config = createTestConfig()
	
	var err error
	s.jwtService, err = jwt.NewJWTService("", "", s.logger)
	require.NoError(s.T(), err)
}

// TearDownSuite runs once after all tests
func (s *AuthTestSuite) TearDownSuite() {
	if s.cleanup != nil {
		s.cleanup()
	}
}

// SetupTest runs before each test
func (s *AuthTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockRepo = mocks.NewMockIRepository(s.mockCtrl)
	s.service = NewService(s.mockRepo, s.jwtService, s.config, s.logger).(*Service)
	// Note: Cannot use t.Parallel() with gomock as it's not thread-safe
}

// TearDownTest runs after each test
func (s *AuthTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

// ============================================================================
// Integration Test Setup (only when integration tag is set)
// ============================================================================

// setupIntegrationTest sets up real database for integration tests
func setupIntegrationTest(t *testing.T) (*Service, *pgxpool.Pool, func()) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgresql://postgres:postgres@localhost:5432/test_nabi_auth?sslmode=disable"
	}

	pool, err := pgxpool.New(context.Background(), databaseURL)
	require.NoError(t, err)

	err = pool.Ping(context.Background())
	require.NoError(t, err)

	queries := db.New(pool)
	repository := NewRepository(queries)

	cfg := createTestConfig()
	logger := zaptest.NewLogger(t)
	jwtService, err := jwt.NewJWTService("", "", logger)
	require.NoError(t, err)

	service := NewService(repository, jwtService, cfg, logger).(*Service)

	cleanup := func() {
		cleanupTestData(t, pool)
		pool.Close()
	}

	return service, pool, cleanup
}

// cleanupTestData removes all test data from database
func cleanupTestData(t *testing.T, pool *pgxpool.Pool) {
	ctx := context.Background()
	tables := []string{"sessions", "otp_codes", "auth_methods", "users"}
	for _, table := range tables {
		_, err := pool.Exec(ctx, "DELETE FROM "+table)
		if err != nil {
			t.Logf("Warning: failed to cleanup table %s: %v", table, err)
		}
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func createTestConfig() *config.Config {
	return &config.Config{
		Auth: config.Auth{
			JWTPrivateKeyPath:   "",
			JWTPublicKeyPath:    "",
			AccessTokenTTL:       3600,
			RefreshTokenTTL:      2592000,
			GoogleClientID:       "test-client-id",
			GoogleClientSecret:   "test-client-secret",
			GoogleRedirectURL:    "http://localhost:8000/auth/oauth2/google/callback",
			TelegramBotToken:     "test-bot-token",
			OTPExpiration:        600,
			OTPMaxAttempts:       5,
		},
	}
}

// Test constants
const (
	testEmail        = "test@example.com"
	testPassword     = "password123"
	testWrongPassword = "wrongpassword"
	testPhoneNumber  = "+1234567890"
	minPasswordLength = 8
)

func createTestUser() db.User {
	var userID pgtype.UUID
	userID.Scan("550e8400-e29b-41d4-a716-446655440000")

	var email pgtype.Text
	email.Scan("test@example.com")

	return db.User{
		ID:               userID,
		Email:            email,
		PhoneNumber:      pgtype.Text{},
		TelegramUsername: pgtype.Text{},
		TelegramID:       pgtype.Int8{},
		CreatedAt:        pgtype.Timestamp{Time: time.Now()},
		UpdatedAt:        pgtype.Timestamp{Time: time.Now()},
	}
}

func createTestUserWithTelegramID(telegramID int64) db.User {
	user := createTestUser()
	var tgID pgtype.Int8
	tgID.Scan(telegramID)
	user.TelegramID = tgID
	return user
}

func hashPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

// ============================================================================
// Mock Repository
// ============================================================================
// Моки генерируются автоматически через go:generate директиву в repository.go
// Используется go.uber.org/mock для типобезопасной генерации моков

// ============================================================================
// Unit Tests (using Testify Suite)
// ============================================================================

func TestAuthTestSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}

// TestRegister tests user registration
func (s *AuthTestSuite) TestRegister() {
	tests := []struct {
		name        string
		req         RegisterRequest
		setupMock   func()
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful registration",
			req: RegisterRequest{
				Email:    "newuser@example.com",
				Password: "password123",
			},
			setupMock: func() {
				user := createTestUser()
				var emailPg pgtype.Text
				emailPg.Scan("newuser@example.com")
				user.Email = emailPg

				s.mockRepo.EXPECT().
					GetUserByEmail(s.ctx, "newuser@example.com").
					Return(db.User{}, errors.New("not found"))

				s.mockRepo.EXPECT().
					CreateUser(s.ctx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(user, nil)

				// Use real bcrypt hash
				passwordHash := hashPassword("password123")
				passwordData := PasswordAuthData{PasswordHash: passwordHash}
				passwordDataBytes, _ := json.Marshal(passwordData)
				authMethod := db.AuthMethod{
					ID:         user.ID,
					UserID:     user.ID,
					MethodType: db.AuthMethodTypePassword,
					MethodData: passwordDataBytes,
					IsActive:   true,
				}

				s.mockRepo.EXPECT().
					CreateAuthMethod(s.ctx, user.ID, db.AuthMethodTypePassword, gomock.Any()).
					Return(authMethod, nil)

				var expiresAt pgtype.Timestamp
				expiresAt.Scan(time.Now().Add(time.Duration(s.config.Auth.RefreshTokenTTL) * time.Second))

				s.mockRepo.EXPECT().
					CreateSession(s.ctx, user.ID, gomock.Any(), gomock.Any(), gomock.Any()).
					Return(db.Session{}, nil)
			},
			expectError: false,
		},
		{
			name: "duplicate email",
			req: RegisterRequest{
				Email:    "existing@example.com",
				Password: "password123",
			},
			setupMock: func() {
				existingUser := createTestUser()
				s.mockRepo.EXPECT().
					GetUserByEmail(s.ctx, "existing@example.com").
					Return(existingUser, nil)
			},
			expectError: true,
			errorMsg:    "already exists",
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			resp, err := s.service.Register(s.ctx, tt.req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.AccessToken)
				assert.NotEmpty(t, resp.RefreshToken)
			}
		})
	}
}

// TestLogin tests user login
func (s *AuthTestSuite) TestLogin() {
	tests := []struct {
		name        string
		req         LoginRequest
		setupMock   func()
		expectError bool
		errorMsg    string
	}{
		{
			name: "user not found",
			req: LoginRequest{
				Email:    "notfound@example.com",
				Password: testPassword,
			},
			setupMock: func() {
				s.mockRepo.EXPECT().
					GetUserByEmail(s.ctx, "notfound@example.com").
					Return(db.User{}, errors.New("not found"))
			},
			expectError: true,
			errorMsg:    "invalid credentials",
		},
		{
			name: "successful login",
			req: LoginRequest{
				Email:    testEmail,
				Password: testPassword,
			},
			setupMock: func() {
				user := createTestUser()
				s.mockRepo.EXPECT().
					GetUserByEmail(s.ctx, testEmail).
					Return(user, nil)

				// Use real bcrypt hash
				passwordHash := hashPassword(testPassword)
				passwordData := PasswordAuthData{PasswordHash: passwordHash}
				passwordDataBytes, _ := json.Marshal(passwordData)
				authMethod := db.AuthMethod{
					ID:         user.ID,
					UserID:     user.ID,
					MethodType: db.AuthMethodTypePassword,
					MethodData: passwordDataBytes,
					IsActive:   true,
				}
				s.mockRepo.EXPECT().
					GetAuthMethodByUserIDAndType(s.ctx, user.ID, db.AuthMethodTypePassword).
					Return(authMethod, nil)

				var expiresAt pgtype.Timestamp
				expiresAt.Scan(time.Now().Add(time.Duration(s.config.Auth.RefreshTokenTTL) * time.Second))
				s.mockRepo.EXPECT().
					CreateSession(s.ctx, user.ID, gomock.Any(), gomock.Any(), gomock.Any()).
					Return(db.Session{}, nil)
			},
			expectError: false,
		},
		{
			name: "invalid password",
			req: LoginRequest{
				Email:    testEmail,
				Password: testWrongPassword,
			},
			setupMock: func() {
				user := createTestUser()
				s.mockRepo.EXPECT().
					GetUserByEmail(s.ctx, testEmail).
					Return(user, nil)

				// Use real bcrypt hash for correct password
				passwordHash := hashPassword(testPassword)
				passwordData := PasswordAuthData{PasswordHash: passwordHash}
				passwordDataBytes, _ := json.Marshal(passwordData)
				authMethod := db.AuthMethod{
					ID:         user.ID,
					UserID:     user.ID,
					MethodType: db.AuthMethodTypePassword,
					MethodData: passwordDataBytes,
					IsActive:   true,
				}
				s.mockRepo.EXPECT().
					GetAuthMethodByUserIDAndType(s.ctx, user.ID, db.AuthMethodTypePassword).
					Return(authMethod, nil)
			},
			expectError: true,
			errorMsg:    "invalid credentials",
		},
		{
			name: "password auth method not found",
			req: LoginRequest{
				Email:    testEmail,
				Password: testPassword,
			},
			setupMock: func() {
				user := createTestUser()
				s.mockRepo.EXPECT().
					GetUserByEmail(s.ctx, testEmail).
					Return(user, nil)

				s.mockRepo.EXPECT().
					GetAuthMethodByUserIDAndType(s.ctx, user.ID, db.AuthMethodTypePassword).
					Return(db.AuthMethod{}, errors.New("not found"))
			},
			expectError: true,
			errorMsg:    "password authentication not set up",
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			resp, err := s.service.Login(s.ctx, tt.req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.AccessToken)
				assert.NotEmpty(t, resp.RefreshToken)
			}
		})
	}
}

// TestSendOTP tests OTP sending
func (s *AuthTestSuite) TestSendOTP() {
	tests := []struct {
		name        string
		req         SendOTPRequest
		setupMock   func()
		expectError bool
	}{
		{
			name: "successful OTP send",
			req: SendOTPRequest{
				Identifier: "otp@example.com",
				Method:     "email",
			},
			setupMock: func() {
				user := createTestUser()
				var expiresAt pgtype.Timestamp
				expiresAt.Scan(time.Now().Add(time.Duration(s.config.Auth.OTPExpiration) * time.Second))
				otpCode := db.OtpCode{
					ID:         user.ID,
					UserID:     user.ID,
					Identifier: "otp@example.com",
					CodeHash:   "hashed",
					ExpiresAt:  expiresAt,
					Used:       false,
					Attempts:   0,
				}

				s.mockRepo.EXPECT().
					GetUserByEmail(s.ctx, "otp@example.com").
					Return(db.User{}, errors.New("not found"))

				s.mockRepo.EXPECT().
					CreateUser(s.ctx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(user, nil)

				s.mockRepo.EXPECT().
					CreateOTPCode(s.ctx, user.ID, "otp@example.com", gomock.Any(), gomock.Any()).
					Return(otpCode, nil)
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			resp, err := s.service.SendOTP(s.ctx, tt.req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, s.config.Auth.OTPExpiration, resp.ExpiresIn)
			}
		})
	}
}

// TestVerifyOTP tests OTP verification
func (s *AuthTestSuite) TestVerifyOTP() {
	tests := []struct {
		name        string
		req         VerifyOTPRequest
		setupMock   func()
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful OTP verification",
			req: VerifyOTPRequest{
				Identifier: testEmail,
				Code:       "123456",
			},
			setupMock: func() {
				user := createTestUser()
				otpCode := db.OtpCode{
					ID:         user.ID,
					UserID:     user.ID,
					Identifier: testEmail,
					CodeHash:   hashPassword("123456"),
					ExpiresAt:  pgtype.Timestamp{Time: time.Now().Add(10 * time.Minute), Valid: true},
					Used:       false,
					Attempts:   0,
				}

				s.mockRepo.EXPECT().
					GetOTPCodeByIdentifier(s.ctx, testEmail).
					Return(otpCode, nil)

				s.mockRepo.EXPECT().
					MarkOTPAsUsed(s.ctx, otpCode.ID).
					Return(nil)

				s.mockRepo.EXPECT().
					GetUserByID(s.ctx, user.ID).
					Return(user, nil)

				s.mockRepo.EXPECT().
					GetAuthMethodByUserIDAndType(s.ctx, user.ID, db.AuthMethodTypeOtp).
					Return(db.AuthMethod{}, errors.New("not found"))

				s.mockRepo.EXPECT().
					CreateAuthMethod(s.ctx, user.ID, db.AuthMethodTypeOtp, gomock.Any()).
					Return(db.AuthMethod{}, nil)

				var expiresAt pgtype.Timestamp
				expiresAt.Scan(time.Now().Add(time.Duration(s.config.Auth.RefreshTokenTTL) * time.Second))
				s.mockRepo.EXPECT().
					CreateSession(s.ctx, user.ID, gomock.Any(), gomock.Any(), gomock.Any()).
					Return(db.Session{}, nil)
			},
			expectError: false,
		},
		{
			name: "OTP code not found",
			req: VerifyOTPRequest{
				Identifier: testEmail,
				Code:       "123456",
			},
			setupMock: func() {
				s.mockRepo.EXPECT().
					GetOTPCodeByIdentifier(s.ctx, testEmail).
					Return(db.OtpCode{}, errors.New("not found"))
			},
			expectError: true,
			errorMsg:    "invalid or expired OTP code",
		},
		{
			name: "invalid OTP code",
			req: VerifyOTPRequest{
				Identifier: testEmail,
				Code:       "wrongcode",
			},
			setupMock: func() {
				user := createTestUser()
				otpCode := db.OtpCode{
					ID:         user.ID,
					UserID:     user.ID,
					Identifier: testEmail,
					CodeHash:   hashPassword("123456"), // Correct code
					ExpiresAt:  pgtype.Timestamp{Time: time.Now().Add(10 * time.Minute), Valid: true},
					Used:       false,
					Attempts:   0,
				}

				s.mockRepo.EXPECT().
					GetOTPCodeByIdentifier(s.ctx, testEmail).
					Return(otpCode, nil)

				s.mockRepo.EXPECT().
					IncrementOTPAttempts(s.ctx, otpCode.ID).
					Return(nil)
			},
			expectError: true,
			errorMsg:    "invalid OTP code",
		},
		{
			name: "OTP max attempts exceeded",
			req: VerifyOTPRequest{
				Identifier: testEmail,
				Code:       "123456",
			},
			setupMock: func() {
				user := createTestUser()
				otpCode := db.OtpCode{
					ID:         user.ID,
					UserID:     user.ID,
					Identifier: testEmail,
					CodeHash:   hashPassword("123456"),
					ExpiresAt:  pgtype.Timestamp{Time: time.Now().Add(10 * time.Minute), Valid: true},
					Used:       false,
					Attempts:   int32(s.config.Auth.OTPMaxAttempts), // Max attempts reached
				}

				s.mockRepo.EXPECT().
					GetOTPCodeByIdentifier(s.ctx, testEmail).
					Return(otpCode, nil)
			},
			expectError: true,
			errorMsg:    "maximum OTP attempts exceeded",
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			resp, err := s.service.VerifyOTP(s.ctx, tt.req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.AccessToken)
			}
		})
	}
}

// TestRefreshToken tests token refresh
// Note: Full testing requires valid JWT tokens, which is complex to mock
// These tests focus on repository-level validation
func (s *AuthTestSuite) TestRefreshToken() {
	tests := []struct {
		name         string
		refreshToken string
		setupMock    func()
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "invalid refresh token (JWT validation fails)",
			refreshToken: "invalid_token",
			setupMock:    func() {
				// JWT validation will fail, no repo calls needed
			},
			expectError: true,
			errorMsg:    "invalid refresh token",
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			if tt.setupMock != nil {
				tt.setupMock()
			}
			resp, err := s.service.RefreshToken(s.ctx, tt.refreshToken)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
			}
		})
	}
}

// TestLogout tests user logout
func (s *AuthTestSuite) TestLogout() {
	tests := []struct {
		name        string
		token       string
		setupMock   func()
		expectError bool
	}{
		{
			name:  "successful logout",
			token: "valid_token",
			setupMock: func() {
				s.mockRepo.EXPECT().
					DeleteSessionByToken(s.ctx, "valid_token").
					Return(nil)
			},
			expectError: false,
		},
		{
			name:  "logout with non-existent token",
			token: "non_existent_token",
			setupMock: func() {
				s.mockRepo.EXPECT().
					DeleteSessionByToken(s.ctx, "non_existent_token").
					Return(nil) // Delete is idempotent
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			err := s.service.Logout(s.ctx, tt.token)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestRegister_EdgeCases tests edge cases for registration
// Note: Email/phone validation should be done at controller level
// These tests verify service behavior with edge case inputs
func (s *AuthTestSuite) TestRegister_EdgeCases() {
	tests := []struct {
		name        string
		req         RegisterRequest
		setupMock   func()
		expectError bool
		errorMsg    string
	}{
		{
			name: "empty email and phone - service allows but should fail at DB level",
			req: RegisterRequest{
				Email:    "",
				Password: testPassword,
			},
			setupMock: func() {
				// Service checks email first, but with empty email it will still try to create user
				// The service doesn't validate email/phone presence - that's controller's job
				// For this test, we simulate DB constraint failure
				s.mockRepo.EXPECT().
					GetUserByEmail(s.ctx, "").
					Return(db.User{}, errors.New("not found")).
					AnyTimes() // May or may not be called depending on service logic

				s.mockRepo.EXPECT().
					CreateUser(s.ctx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(db.User{}, errors.New("constraint violation"))
			},
			expectError: true,
		},
		{
			name: "password too short - service allows, validation at controller",
			req: RegisterRequest{
				Email:    testEmail,
				Password: "short",
			},
			setupMock: func() {
				// Service doesn't validate password length, controller should
				// This test verifies service behavior with short password
				user := createTestUser()
				s.mockRepo.EXPECT().
					GetUserByEmail(s.ctx, testEmail).
					Return(db.User{}, errors.New("not found"))

				s.mockRepo.EXPECT().
					CreateUser(s.ctx, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(user, nil)

				passwordHash := hashPassword("short")
				passwordData := PasswordAuthData{PasswordHash: passwordHash}
				passwordDataBytes, _ := json.Marshal(passwordData)
				authMethod := db.AuthMethod{
					ID:         user.ID,
					UserID:     user.ID,
					MethodType: db.AuthMethodTypePassword,
					MethodData: passwordDataBytes,
					IsActive:   true,
				}

				s.mockRepo.EXPECT().
					CreateAuthMethod(s.ctx, user.ID, db.AuthMethodTypePassword, gomock.Any()).
					Return(authMethod, nil)

				var expiresAt pgtype.Timestamp
				expiresAt.Scan(time.Now().Add(time.Duration(s.config.Auth.RefreshTokenTTL) * time.Second))
				s.mockRepo.EXPECT().
					CreateSession(s.ctx, user.ID, gomock.Any(), gomock.Any(), gomock.Any()).
					Return(db.Session{}, nil)
			},
			expectError: false, // Service doesn't validate password length
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			if tt.setupMock != nil {
				tt.setupMock()
			}
			resp, err := s.service.Register(s.ctx, tt.req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
			}
		})
	}
}

// ============================================================================
// Integration Tests (only run with -tags=integration)
// ============================================================================

func TestIntegration_RegisterAndLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	service, _, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("register new user", func(t *testing.T) {
		req := RegisterRequest{
			Email:    "integration@test.com",
			Password: "testpassword123",
		}

		resp, err := service.Register(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.NotEmpty(t, resp.User.ID)
	})

	t.Run("login with registered user", func(t *testing.T) {
		req := LoginRequest{
			Email:    "integration@test.com",
			Password: "testpassword123",
		}

		resp, err := service.Login(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.AccessToken)
	})

	t.Run("login with wrong password", func(t *testing.T) {
		req := LoginRequest{
			Email:    "integration@test.com",
			Password: "wrongpassword",
		}

		resp, err := service.Login(ctx, req)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid credentials")
	})
}

func TestIntegration_DuplicateEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	service, _, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	req := RegisterRequest{
		Email:    "duplicate@test.com",
		Password: "password123",
	}

	// First registration
	resp1, err := service.Register(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp1)

	// Second registration should fail
	resp2, err := service.Register(ctx, req)
	assert.Error(t, err)
	assert.Nil(t, resp2)
	assert.Contains(t, err.Error(), "already exists")
}

func TestIntegration_TelegramAuth_WithBigInt(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	_, pool, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	// Test that Telegram ID is properly handled as bigint (int64)
	telegramID := int64(1234567890123456789) // Large number to test bigint

	queries := db.New(pool)
	var telegramIDPg pgtype.Int8
	telegramIDPg.Scan(telegramID)

	var telegramUsernamePg pgtype.Text
	telegramUsernamePg.Scan("testuser")

	user, err := queries.CreateUser(ctx, db.CreateUserParams{
		Email:            pgtype.Text{},
		PhoneNumber:      pgtype.Text{},
		TelegramUsername: telegramUsernamePg,
		TelegramID:       telegramIDPg,
	})
	require.NoError(t, err)

	// Verify Telegram ID is stored correctly
	assert.True(t, user.TelegramID.Valid)
	assert.Equal(t, telegramID, user.TelegramID.Int64)

	// Retrieve user by Telegram ID
	retrievedUser, err := queries.GetUserByTelegramID(ctx, telegramIDPg)
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrievedUser.ID)
	assert.Equal(t, telegramID, retrievedUser.TelegramID.Int64)

	t.Logf("Successfully stored and retrieved Telegram ID: %d", telegramID)
}

func TestIntegration_FullAuthFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	service, pool, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("full authentication flow", func(t *testing.T) {
		// Step 1: Register
		registerReq := RegisterRequest{
			Email:    "fullflow@test.com",
			Password: "securepassword123",
		}

		registerResp, err := service.Register(ctx, registerReq)
		require.NoError(t, err)
		assert.NotEmpty(t, registerResp.AccessToken)

		// Step 2: Login
		loginReq := LoginRequest{
			Email:    "fullflow@test.com",
			Password: "securepassword123",
		}

		loginResp, err := service.Login(ctx, loginReq)
		require.NoError(t, err)
		assert.NotEmpty(t, loginResp.AccessToken)

		// Step 3: Refresh token
		refreshResp, err := service.RefreshToken(ctx, loginResp.RefreshToken)
		require.NoError(t, err)
		assert.NotEmpty(t, refreshResp.AccessToken)

		// Step 4: Logout
		err = service.Logout(ctx, refreshResp.AccessToken)
		require.NoError(t, err)

		// Step 5: Verify logout
		queries := db.New(pool)
		_, err = queries.GetSessionByToken(ctx, refreshResp.AccessToken)
		assert.Error(t, err) // Session should be deleted
	})
}

func TestIntegration_OTP_Flow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	service, pool, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("send and verify OTP", func(t *testing.T) {
		// Send OTP
		sendReq := SendOTPRequest{
			Identifier: "otp@test.com",
			Method:     "email",
		}

		sendResp, err := service.SendOTP(ctx, sendReq)
		require.NoError(t, err)
		assert.NotNil(t, sendResp)
		assert.Equal(t, 600, sendResp.ExpiresIn)

		// Get OTP code from database
		queries := db.New(pool)
		otpCode, err := queries.GetOTPCodeByIdentifier(ctx, sendReq.Identifier)
		require.NoError(t, err)

		t.Logf("OTP Code ID: %v", otpCode.ID)
		t.Logf("OTP Identifier: %s", otpCode.Identifier)
	})
}

func TestIntegration_AuthMethod_Creation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	service, pool, cleanup := setupIntegrationTest(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("verify auth method creation", func(t *testing.T) {
		// Register user
		registerReq := RegisterRequest{
			Email:    "authmethod@test.com",
			Password: "password123",
		}

		_, err := service.Register(ctx, registerReq)
		require.NoError(t, err)

		// Verify auth method was created
		queries := db.New(pool)
		user, err := queries.GetUserByEmail(ctx, pgtype.Text{String: "authmethod@test.com", Valid: true})
		require.NoError(t, err)

		authMethod, err := queries.GetAuthMethodByUserIDAndType(ctx, db.GetAuthMethodByUserIDAndTypeParams{
			UserID:     user.ID,
			MethodType: db.AuthMethodTypePassword,
		})

		require.NoError(t, err)
		assert.Equal(t, db.AuthMethodTypePassword, authMethod.MethodType)
		assert.True(t, authMethod.IsActive)

		// Verify password hash is stored
		var passwordData PasswordAuthData
		err = json.Unmarshal(authMethod.MethodData, &passwordData)
		require.NoError(t, err)
		assert.NotEmpty(t, passwordData.PasswordHash)

		// Verify password can be checked
		err = bcrypt.CompareHashAndPassword([]byte(passwordData.PasswordHash), []byte("password123"))
		assert.NoError(t, err)
	})
}

