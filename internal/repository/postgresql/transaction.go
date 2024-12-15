package postgresql

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/agungcandra/snap/pkg/database"
)

// WithTx represent wrapper for running query inside transaction block
type WithTx interface {
	WithTx(tx pgx.Tx) *Queries
}

// TransactionActionFn represents function that need to be executed inside transaction block
type TransactionActionFn func(qtx Querier) error

func TransactionWrapper(ctx context.Context, txStarter database.PgxPool, q WithTx, fn TransactionActionFn) error {
	tx, err := txStarter.Begin(ctx)
	if err != nil {
		return err
	}

	if err = fn(q.WithTx(tx)); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}
