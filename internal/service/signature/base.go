package signature

import (
	"context"
	"crypto/sha256"
	"github.com/agungcandra/snap/internal/repository/postgresql"
	"github.com/agungcandra/snap/pkg/database"
	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultPbkdfIteration = 100_000
	defaultKeyLen         = 32
)

type repositoryWithoutTx interface {
	InsertKey(ctx context.Context, arg postgresql.InsertKeyParams) (int64, error)
	InsertNonce(ctx context.Context, arg postgresql.InsertNonceParams) error
	InsertSalt(ctx context.Context, arg postgresql.InsertSaltParams) error
}

type repository interface {
	postgresql.WithTx
	repositoryWithoutTx
}

// Signature TODO comment
type Signature struct {
	txStarter           database.PgxPool
	secretKey           string
	signatureRepository repository
}

// NewSignature initialize new signature usecase
func NewSignature(pool database.PgxPool, signatureRepository repository, secretKey string) *Signature {
	return &Signature{
		txStarter:           pool,
		secretKey:           secretKey,
		signatureRepository: signatureRepository,
	}
}

// GenerateKey helper function for generate KEK key derives from password, salt and iteration count
func (svc *Signature) GenerateKey(salt []byte) []byte {
	return pbkdf2.Key([]byte(svc.secretKey), salt, defaultPbkdfIteration, defaultKeyLen, sha256.New)
}

func (svc *Signature) Transaction(ctx context.Context, fn postgresql.TransactionActionFn) error {
	return postgresql.TransactionWrapper(ctx, svc.txStarter, svc.signatureRepository, fn)
}
