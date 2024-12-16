package crypto

import "errors"

var (
	// ErrFailedInsertKey error happen when saving key to repository
	ErrFailedInsertKey = errors.New("failed to save key")
	// ErrFailedInsertNonce error happen when saving nonce to repository
	ErrFailedInsertNonce = errors.New("failed to save nonce")
	// ErrFailedInsertSalt error happen when saving salt to repository
	ErrFailedInsertSalt = errors.New("failed to save salt")
	// ErrInvalidClientID error because client id is not parseable to uuid
	ErrInvalidClientID = errors.New("invalid client id")
	// ErrInvalidKeyGeneration error because invalid key generation algorithm
	ErrInvalidKeyGeneration = errors.New("invalid key generation")
)
