package signature

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

// Signature TODO comment
type Signature struct {
	txStarter           database.PgxPool
	signatureRepository repository
}

// NewSignature initialize new signature usecase
func NewSignature(pool database.PgxPool, signatureRepository repository) *Signature {
	return &Signature{
		txStarter:           pool,
		signatureRepository: signatureRepository,
	}
}

func (svc *Signature) Transaction(ctx context.Context, fn postgresql.TransactionActionFn) error {
	return postgresql.TransactionWrapper(ctx, svc.txStarter, svc.signatureRepository, fn)
}
