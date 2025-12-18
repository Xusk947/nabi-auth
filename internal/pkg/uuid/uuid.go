package uuid

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// GenerateUUIDv7 generates a UUIDv7 (time-ordered UUID)
// Note: Using UUIDv4 for now as UUIDv7 support in Go is limited
// TODO: Replace with proper UUIDv7 library (e.g., github.com/dombox/uuidv7) when available
func GenerateUUIDv7() (uuid.UUID, error) {
	// For now using v4, but structure allows easy swap to UUIDv7
	return uuid.New(), nil
}

// ToPgtypeUUID converts uuid.UUID to pgtype.UUID
func ToPgtypeUUID(u uuid.UUID) pgtype.UUID {
	var pgUUID pgtype.UUID
	_ = pgUUID.Scan(u.String())
	return pgUUID
}

// FromPgtypeUUID converts pgtype.UUID to uuid.UUID
func FromPgtypeUUID(pgUUID pgtype.UUID) (uuid.UUID, error) {
	if !pgUUID.Valid {
		return uuid.Nil, nil
	}
	// Convert bytes array to slice for parsing
	if len(pgUUID.Bytes) == 16 {
		bytesSlice := pgUUID.Bytes[:]
		return uuid.FromBytes(bytesSlice)
	}
	return uuid.Nil, nil
}

