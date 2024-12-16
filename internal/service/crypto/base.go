package crypto

import (
	"context"

	"github.com/agungcandra/snap/internal/repository/postgresql"
	"github.com/agungcandra/snap/pkg/database"
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

// Crypto TODO comment
type Crypto struct {
	txStarter           database.PgxPool
	signatureRepository repository
}

// NewCrypto initialize new signature usecase
func NewCrypto(pool database.PgxPool, signatureRepository repository) *Crypto {
	return &Crypto{
		txStarter:           pool,
		signatureRepository: signatureRepository,
	}
}

func (svc *Crypto) Transaction(ctx context.Context, fn postgresql.TransactionActionFn) error {
	return postgresql.TransactionWrapper(ctx, svc.txStarter, svc.signatureRepository, fn)
}
