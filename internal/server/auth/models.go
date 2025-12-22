package auth

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Request DTOs

type RegisterRequest struct {
	Email       string `json:"email" validate:"required,email"`
	PhoneNumber string `json:"phone_number" validate:"omitempty"`
	Password    string `json:"password" validate:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type SendOTPRequest struct {
	Identifier string `json:"identifier" validate:"required"` // email or phone
	Method     string `json:"method" validate:"required,oneof=email sms"`
}

type VerifyOTPRequest struct {
	Identifier string `json:"identifier" validate:"required"`
	Code       string `json:"code" validate:"required,len=6"`
}

type TelegramVerifyRequest struct {
	InitData string `json:"init_data" validate:"required"` // Telegram WebApp initData
}

// Response DTOs

type AuthResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int64    `json:"expires_in"`
	User         UserInfo `json:"user"`
}

type UserInfo struct {
	ID               string `json:"id"`
	Email            string `json:"email,omitempty"`
	PhoneNumber      string `json:"phone_number,omitempty"`
	TelegramUsername string `json:"telegram_username,omitempty"`
}

type OTPResponse struct {
	Message   string `json:"message"`
	ExpiresIn int    `json:"expires_in"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// Internal models

type PasswordAuthData struct {
	PasswordHash string `json:"password_hash"`
}

type GoogleAuthData struct {
	GoogleID     string `json:"google_id"`
	Email        string `json:"email"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type TelegramAuthData struct {
	TelegramID int64  `json:"telegram_id"`
	Username   string `json:"username,omitempty"`
	FirstName  string `json:"first_name,omitempty"`
	LastName   string `json:"last_name,omitempty"`
	PhotoURL   string `json:"photo_url,omitempty"`
	AuthDate   int64  `json:"auth_date"`
	Hash       string `json:"hash"`
}

// Helper functions

func ToUserInfo(userID pgtype.UUID, email, phoneNumber, telegramUsername pgtype.Text) UserInfo {
	info := UserInfo{}
	if userID.Valid && len(userID.Bytes) == 16 {
		// Convert UUID bytes to string representation
		bytesSlice := userID.Bytes[:]
		uuidStr, _ := uuid.FromBytes(bytesSlice)
		info.ID = uuidStr.String()
	}
	if email.Valid {
		info.Email = email.String
	}
	if phoneNumber.Valid {
		info.PhoneNumber = phoneNumber.String
	}
	if telegramUsername.Valid {
		info.TelegramUsername = telegramUsername.String
	}
	return info
}
