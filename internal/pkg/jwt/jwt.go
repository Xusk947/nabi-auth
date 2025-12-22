package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"nabi-auth/internal/pkg/config"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	logger     *zap.Logger
}

type Claims struct {
	UserID pgtype.UUID `json:"user_id"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// NewJWTService creates a new JWT service
// If key files exist, loads them; otherwise generates new keys
func NewJWTService(privateKeyPath, publicKeyPath string, logger *zap.Logger) (*JWTService, error) {
	service := &JWTService{
		logger: logger,
	}

	// Try to load existing keys
	if privateKeyPath != "" && publicKeyPath != "" {
		if err := service.loadKeys(privateKeyPath, publicKeyPath); err == nil {
			logger.Info("Loaded existing JWT keys", zap.String("private", privateKeyPath), zap.String("public", publicKeyPath))
			return service, nil
		} else {
			logger.Warn("Failed to load existing keys, generating new ones", zap.Error(err))
		}
	}

	// Generate new keys
	if err := service.generateKeys(); err != nil {
		return nil, fmt.Errorf("failed to generate JWT keys: %w", err)
	}

	// Save keys if paths are provided
	if privateKeyPath != "" && publicKeyPath != "" {
		if err := service.saveKeys(privateKeyPath, publicKeyPath); err != nil {
			logger.Warn("Failed to save JWT keys", zap.Error(err))
		} else {
			logger.Info("Generated and saved new JWT keys", zap.String("private", privateKeyPath), zap.String("public", publicKeyPath))
		}
	}

	return service, nil
}

// GenerateKeys generates RSA key pair for JWT signing
func (j *JWTService) generateKeys() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	j.privateKey = key
	j.publicKey = &key.PublicKey
	return nil
}

// LoadKeys loads RSA keys from files
func (j *JWTService) loadKeys(privateKeyPath, publicKeyPath string) error {
	// Load private key
	privateKeyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}

	privateBlock, _ := pem.Decode(privateKeyData)
	if privateBlock == nil {
		return errors.New("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	j.privateKey = privateKey

	// Load public key
	publicKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}

	publicBlock, _ := pem.Decode(publicKeyData)
	if publicBlock == nil {
		return errors.New("failed to decode public key PEM")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(publicBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	j.publicKey = publicKey
	return nil
}

// SaveKeys saves RSA keys to files
func (j *JWTService) saveKeys(privateKeyPath, publicKeyPath string) error {
	// Save private key
	privateKeyData := x509.MarshalPKCS1PrivateKey(j.privateKey)
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyData,
	})

	if err := os.WriteFile(privateKeyPath, privatePEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Save public key
	publicKeyData := x509.MarshalPKCS1PublicKey(j.publicKey)
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyData,
	})

	if err := os.WriteFile(publicKeyPath, publicPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// GenerateTokenPair generates access and refresh tokens
func (j *JWTService) GenerateTokenPair(userID pgtype.UUID, accessTokenTTL, refreshTokenTTL time.Duration) (*TokenPair, error) {
	now := time.Now()

	// Generate access token
	accessClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(j.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(refreshTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(j.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
	}, nil
}

// ValidateToken validates a JWT token and returns the claims
func (j *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}

// GetPublicKeyPEM returns the public key in PEM format
func (j *JWTService) GetPublicKeyPEM() ([]byte, error) {
	if j.publicKey == nil {
		return nil, errors.New("public key not initialized")
	}

	publicKeyData := x509.MarshalPKCS1PublicKey(j.publicKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyData,
	}), nil
}

var Module = fx.Module(
	"jwt",
	fx.Provide(func(cfg *config.Config, logger *zap.Logger) (*JWTService, error) {
		return NewJWTService(cfg.Auth.JWTPrivateKeyPath, cfg.Auth.JWTPublicKeyPath, logger)
	}),
)
