package crypto

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"

	"github.com/agungcandra/snap/internal/repository/postgresql"
	"github.com/agungcandra/snap/pkg/logger"
)

func (svc *Crypto) SaveClientRSAKey(ctx context.Context, clientID string, privateKey []byte) error {
	encryptedPrivateKey, err := svc.Encrypt(privateKey, RandGenerator(aes256KeyLength))
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %v", err)
	}

	return svc.Transaction(ctx, func(qtx postgresql.Querier) error {
		return svc.SaveKey(ctx, qtx, clientID, encryptedPrivateKey)
	})
}

func (svc *Crypto) SaveKey(ctx context.Context, repo repositoryWithoutTx, clientID string, encryptedKey Encrypted) error {
	var client pgtype.UUID
	if err := client.Scan(clientID); err != nil {
		logger.ErrorWithContext(ctx, err, zap.String("client_id", clientID))
		return ErrInvalidClientID
	}

	key, err := repo.InsertKey(ctx, postgresql.InsertKeyParams{
		ClientID:     client,
		EncryptedKey: encryptedKey.Payload,
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
