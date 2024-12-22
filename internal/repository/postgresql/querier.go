// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.22.0

package postgresql

import (
	"context"
)

type Querier interface {
	FindLatestClientKeyByName(ctx context.Context, name string) (ClientKey, error)
	FindLatestKeyStorageByName(ctx context.Context, name string) (KeyStorage, error)
	InsertClient(ctx context.Context, arg InsertClientParams) (Client, error)
	InsertClientKey(ctx context.Context, arg InsertClientKeyParams) error
	InsertKeyStorage(ctx context.Context, arg InsertKeyStorageParams) error
}

var _ Querier = (*Queries)(nil)
