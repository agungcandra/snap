package accesstoken

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"

	"github.com/agungcandra/snap/internal/repository/crypto"
	"github.com/agungcandra/snap/internal/repository/postgresql"
	"github.com/agungcandra/snap/pkg/logger"
)

var (
	// NewClientKeyGenerator helper function for generate new uuid key for client
	NewClientKeyGenerator = uuid.NewString
)

// CreateClientParams parameter for create new client
type CreateClientParams struct {
	Name      string
	PublicKey []byte
}

// CreateClient create new client and store the client public key
// PublicKey in rsa public key encoded in DER format, other format will marked as invalid and return ErrInvalidParsePublicKey
func (svc *AccessToken) CreateClient(ctx context.Context, params CreateClientParams) (postgresql.Client, error) {
	publicKey, err := x509.ParsePKIXPublicKey(params.PublicKey)
	if err != nil {
		logger.ErrorWithContext(ctx, err, zap.String("tags", "create_client"))
		return postgresql.Client{}, ErrInvalidParsePublicKey
	}

	if _, ok := publicKey.(*rsa.PublicKey); !ok {
		return postgresql.Client{}, ErrInvalidParsePublicKey
	}

	newClientID := NewClientKeyGenerator()
	var clientID pgtype.UUID
	if err = clientID.Scan(newClientID); err != nil {
		logger.ErrorWithContext(ctx, err)
		return postgresql.Client{}, ErrFailedGenerateClientID
	}

	encryptedPublicKey, err := svc.cryptoProvider.Encrypt(ctx, crypto.EncryptRequest{
		Name:      newClientID,
		PlainText: params.PublicKey,
	})
	if err != nil {
		return postgresql.Client{}, err
	}

	client, err := svc.repo.InsertClient(ctx, postgresql.InsertClientParams{
		ID:        clientID,
		Name:      params.Name,
		PublicKey: encryptedPublicKey.Ciphertext,
	})
	if err != nil {
		logger.ErrorWithContext(ctx, err, zap.String("tags", "create_client"))
		return postgresql.Client{}, ErrFailedCreateClient
	}

	return client, nil
}
