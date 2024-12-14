package signature

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/agungcandra/snap/internal/repository/postgresql"
	"github.com/agungcandra/snap/pkg/logger"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"io"
)

const (
	nonceSize = 12
	saltSize  = 16
)

type EncryptedKey struct {
	EncryptedKey []byte
	Salt         []byte
	Nonce        []byte
}

func (svc *Signature) EncryptKey(privateKey []byte, kek []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	nonce := make([]byte, nonceSize)
	// Need to io.ReadFull when generate noonce to ensure that all nonce block is filled to ensure uniquness
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed generate nonce: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	cipherText := aesGCM.Seal(nil, nonce, privateKey, nil)
	return cipherText, nonce, nil
}

func (svc *Signature) EncryptRSAKey(privateKey []byte) (EncryptedKey, error) {
	salt := make([]byte, saltSize)
	// Use rand.Read is enough for generate salt
	if _, err := rand.Read(salt); err != nil {
		return EncryptedKey{}, fmt.Errorf("failed to generate salt: %v", err)
	}

	kek := svc.GenerateKey(salt)
	encryptedPrivateKey, nonce, err := svc.EncryptKey(privateKey, kek)
	if err != nil {
		return EncryptedKey{}, fmt.Errorf("failed to encrypt private key: %v", err)
	}

	return EncryptedKey{
		EncryptedKey: encryptedPrivateKey,
		Salt:         salt,
		Nonce:        nonce,
	}, nil
}

func (svc *Signature) SaveClientRSAKey(ctx context.Context, clientID string, privateKey []byte) error {
	encryptedPrivateKey, err := svc.EncryptRSAKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %v", err)
	}

	return svc.Transaction(ctx, func(qtx postgresql.Querier) error {
		return svc.SaveKey(ctx, qtx, clientID, encryptedPrivateKey)
	})
}

func (svc *Signature) SaveKey(ctx context.Context, repo repositoryWithoutTx, clientID string, encryptedKey EncryptedKey) error {
	var client pgtype.UUID
	if err := client.Scan(clientID); err != nil {
		logger.ErrorWithContext(ctx, err, zap.String("client_id", clientID))
		return ErrInvalidClientID
	}

	key, err := repo.InsertKey(ctx, postgresql.InsertKeyParams{
		ClientID:     client,
		EncryptedKey: encryptedKey.EncryptedKey,
	})
	if err != nil {
		logger.ErrorWithContext(ctx, err, zap.Stack("stacktrace"))
		return ErrFailedInsertKey
	}

	if err = repo.InsertNonce(ctx, postgresql.InsertNonceParams{
		KeyID: key,
		Nonce: encryptedKey.Nonce,
	}); err != nil {
		logger.ErrorWithContext(ctx, err, zap.Stack("stacktrace"))
		return ErrFailedInsertNonce
	}

	if err = repo.InsertSalt(ctx, postgresql.InsertSaltParams{
		KeyID: key,
		Salt:  encryptedKey.Salt,
	}); err != nil {
		logger.ErrorWithContext(ctx, err, zap.Stack("stacktrace"))
		return ErrFailedInsertSalt
	}

	return nil
}
