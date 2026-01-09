package auth

import (
	"context"
	"encoding/json"

	db "nabi-auth/db/gen/queries.go"

	"github.com/jackc/pgx/v5/pgtype"
)

//go:generate mockgen -source=repository.go -destination=mocks/repository_mock.go -package=mocks

type IRepository interface {
	CreateUser(ctx context.Context, email, phoneNumber, telegramUsername pgtype.Text, telegramID pgtype.Int8, avatarURL pgtype.Text) (db.User, error)
	GetUserByID(ctx context.Context, userID pgtype.UUID) (db.User, error)
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetUserByPhone(ctx context.Context, phoneNumber string) (db.User, error)
	GetUserByTelegramID(ctx context.Context, telegramID int64) (db.User, error)
	GetUserByTelegramUsername(ctx context.Context, username string) (db.User, error)
	UpdateUser(ctx context.Context, params db.UpdateUserParams) (db.User, error)

	CreateAuthMethod(ctx context.Context, userID pgtype.UUID, methodType db.AuthMethodType, methodData interface{}) (db.AuthMethod, error)
	GetAuthMethodByUserIDAndType(ctx context.Context, userID pgtype.UUID, methodType db.AuthMethodType) (db.AuthMethod, error)
	UpdateAuthMethod(ctx context.Context, methodID pgtype.UUID, methodData interface{}, isActive bool) (db.AuthMethod, error)

	CreateSession(ctx context.Context, userID pgtype.UUID, token, refreshToken string, expiresAt pgtype.Timestamp) (db.Session, error)
	GetSessionByToken(ctx context.Context, token string) (db.Session, error)
	GetSessionByRefreshToken(ctx context.Context, refreshToken string) (db.Session, error)
	DeleteSession(ctx context.Context, sessionID pgtype.UUID) error
	DeleteSessionByToken(ctx context.Context, token string) error
	DeleteSessionByRefreshToken(ctx context.Context, refreshToken string) error

	CreateOTPCode(ctx context.Context, userID pgtype.UUID, identifier, codeHash string, expiresAt pgtype.Timestamp) (db.OtpCode, error)
	GetOTPCodeByIdentifier(ctx context.Context, identifier string) (db.OtpCode, error)
	MarkOTPAsUsed(ctx context.Context, otpID pgtype.UUID) error
	IncrementOTPAttempts(ctx context.Context, otpID pgtype.UUID) error
}

type Repository struct {
	queries *db.Queries
}

func NewRepository(queries *db.Queries) IRepository {
	return &Repository{
		queries: queries,
	}
}

func (r *Repository) CreateUser(ctx context.Context, email, phoneNumber, telegramUsername pgtype.Text, telegramID pgtype.Int8, avatarURL pgtype.Text) (db.User, error) {
	row, err := r.queries.CreateUser(ctx, db.CreateUserParams{
		Email:            email,
		PhoneNumber:      phoneNumber,
		TelegramUsername: telegramUsername,
		TelegramID:       telegramID,
		AvatarUrl:        avatarURL,
	})
	if err != nil {
		return db.User{}, err
	}
	return db.User{
		ID:               row.ID,
		Email:            row.Email,
		PhoneNumber:      row.PhoneNumber,
		TelegramUsername: row.TelegramUsername,
		TelegramID:       row.TelegramID,
		AvatarUrl:        row.AvatarUrl,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}, nil
}

func (r *Repository) GetUserByID(ctx context.Context, userID pgtype.UUID) (db.User, error) {
	row, err := r.queries.GetUserByID(ctx, userID)
	if err != nil {
		return db.User{}, err
	}
	return db.User{
		ID:               row.ID,
		Email:            row.Email,
		PhoneNumber:      row.PhoneNumber,
		TelegramUsername: row.TelegramUsername,
		TelegramID:       row.TelegramID,
		AvatarUrl:        row.AvatarUrl,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}, nil
}

func (r *Repository) GetUserByEmail(ctx context.Context, email string) (db.User, error) {
	var emailPg pgtype.Text
	if err := emailPg.Scan(email); err != nil {
		return db.User{}, err
	}
	row, err := r.queries.GetUserByEmail(ctx, emailPg)
	if err != nil {
		return db.User{}, err
	}
	return db.User{
		ID:               row.ID,
		Email:            row.Email,
		PhoneNumber:      row.PhoneNumber,
		TelegramUsername: row.TelegramUsername,
		TelegramID:       row.TelegramID,
		AvatarUrl:        row.AvatarUrl,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}, nil
}

func (r *Repository) GetUserByPhone(ctx context.Context, phoneNumber string) (db.User, error) {
	var phonePg pgtype.Text
	if err := phonePg.Scan(phoneNumber); err != nil {
		return db.User{}, err
	}
	row, err := r.queries.GetUserByPhone(ctx, phonePg)
	if err != nil {
		return db.User{}, err
	}
	return db.User{
		ID:               row.ID,
		Email:            row.Email,
		PhoneNumber:      row.PhoneNumber,
		TelegramUsername: row.TelegramUsername,
		TelegramID:       row.TelegramID,
		AvatarUrl:        row.AvatarUrl,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}, nil
}

func (r *Repository) GetUserByTelegramID(ctx context.Context, telegramID int64) (db.User, error) {
	var tgID pgtype.Int8
	if err := tgID.Scan(telegramID); err != nil {
		return db.User{}, err
	}
	row, err := r.queries.GetUserByTelegramID(ctx, tgID)
	if err != nil {
		return db.User{}, err
	}
	return db.User{
		ID:               row.ID,
		Email:            row.Email,
		PhoneNumber:      row.PhoneNumber,
		TelegramUsername: row.TelegramUsername,
		TelegramID:       row.TelegramID,
		AvatarUrl:        row.AvatarUrl,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}, nil
}

func (r *Repository) GetUserByTelegramUsername(ctx context.Context, username string) (db.User, error) {
	var usernamePg pgtype.Text
	if err := usernamePg.Scan(username); err != nil {
		return db.User{}, err
	}
	row, err := r.queries.GetUserByTelegramUsername(ctx, usernamePg)
	if err != nil {
		return db.User{}, err
	}
	return db.User{
		ID:               row.ID,
		Email:            row.Email,
		PhoneNumber:      row.PhoneNumber,
		TelegramUsername: row.TelegramUsername,
		TelegramID:       row.TelegramID,
		AvatarUrl:        row.AvatarUrl,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}, nil
}

func (r *Repository) UpdateUser(ctx context.Context, params db.UpdateUserParams) (db.User, error) {
	row, err := r.queries.UpdateUser(ctx, params)
	if err != nil {
		return db.User{}, err
	}
	return db.User{
		ID:               row.ID,
		Email:            row.Email,
		PhoneNumber:      row.PhoneNumber,
		TelegramUsername: row.TelegramUsername,
		TelegramID:       row.TelegramID,
		AvatarUrl:        row.AvatarUrl,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}, nil
}

func (r *Repository) CreateAuthMethod(ctx context.Context, userID pgtype.UUID, methodType db.AuthMethodType, methodData interface{}) (db.AuthMethod, error) {
	dataBytes, err := json.Marshal(methodData)
	if err != nil {
		return db.AuthMethod{}, err
	}

	return r.queries.CreateAuthMethod(ctx, db.CreateAuthMethodParams{
		UserID:     userID,
		MethodType: methodType,
		MethodData: dataBytes,
		IsActive:   true,
	})
}

func (r *Repository) GetAuthMethodByUserIDAndType(ctx context.Context, userID pgtype.UUID, methodType db.AuthMethodType) (db.AuthMethod, error) {
	return r.queries.GetAuthMethodByUserIDAndType(ctx, db.GetAuthMethodByUserIDAndTypeParams{
		UserID:     userID,
		MethodType: methodType,
	})
}

func (r *Repository) UpdateAuthMethod(ctx context.Context, methodID pgtype.UUID, methodData interface{}, isActive bool) (db.AuthMethod, error) {
	var dataBytes []byte
	var err error

	if methodData != nil {
		dataBytes, err = json.Marshal(methodData)
		if err != nil {
			return db.AuthMethod{}, err
		}
	}

	return r.queries.UpdateAuthMethod(ctx, db.UpdateAuthMethodParams{
		ID:         methodID,
		MethodData: dataBytes,
		IsActive:   isActive,
	})
}

func (r *Repository) CreateSession(ctx context.Context, userID pgtype.UUID, token, refreshToken string, expiresAt pgtype.Timestamp) (db.Session, error) {
	var refreshTokenPg pgtype.Text
	if err := refreshTokenPg.Scan(refreshToken); err != nil {
		return db.Session{}, err
	}

	return r.queries.CreateSession(ctx, db.CreateSessionParams{
		UserID:       userID,
		Token:        token,
		RefreshToken: refreshTokenPg,
		ExpiresAt:    expiresAt,
	})
}

func (r *Repository) GetSessionByToken(ctx context.Context, token string) (db.Session, error) {
	return r.queries.GetSessionByToken(ctx, token)
}

func (r *Repository) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (db.Session, error) {
	var refreshTokenPg pgtype.Text
	if err := refreshTokenPg.Scan(refreshToken); err != nil {
		return db.Session{}, err
	}
	return r.queries.GetSessionByRefreshToken(ctx, refreshTokenPg)
}

func (r *Repository) DeleteSession(ctx context.Context, sessionID pgtype.UUID) error {
	return r.queries.DeleteSession(ctx, sessionID)
}

func (r *Repository) DeleteSessionByToken(ctx context.Context, token string) error {
	return r.queries.DeleteSessionByToken(ctx, token)
}

func (r *Repository) DeleteSessionByRefreshToken(ctx context.Context, refreshToken string) error {
	var refreshTokenPg pgtype.Text
	if err := refreshTokenPg.Scan(refreshToken); err != nil {
		return err
	}
	return r.queries.DeleteSessionByRefreshToken(ctx, refreshTokenPg)
}

func (r *Repository) CreateOTPCode(ctx context.Context, userID pgtype.UUID, identifier, codeHash string, expiresAt pgtype.Timestamp) (db.OtpCode, error) {
	return r.queries.CreateOTPCode(ctx, db.CreateOTPCodeParams{
		UserID:     userID,
		Identifier: identifier,
		CodeHash:   codeHash,
		ExpiresAt:  expiresAt,
	})
}

func (r *Repository) GetOTPCodeByIdentifier(ctx context.Context, identifier string) (db.OtpCode, error) {
	return r.queries.GetOTPCodeByIdentifier(ctx, identifier)
}

func (r *Repository) MarkOTPAsUsed(ctx context.Context, otpID pgtype.UUID) error {
	return r.queries.MarkOTPAsUsed(ctx, otpID)
}

func (r *Repository) IncrementOTPAttempts(ctx context.Context, otpID pgtype.UUID) error {
	return r.queries.IncrementOTPAttempts(ctx, otpID)
}
