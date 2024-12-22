package database

import (
	"context"

	"github.com/agungcandra/snap/internal/repository/postgresql"
)

type EncryptionKeyRepository interface {
	InsertKeyStorage(ctx context.Context, arg postgresql.InsertKeyStorageParams) error
	FindLatestKeyStorageByName(ctx context.Context, name string) (postgresql.KeyStorage, error)
}

type EncryptionKeyRetriever interface {
	GenerateKey(ctx context.Context, name string) ([]byte, error)
	RetrieveKey(ctx context.Context, name string) ([]byte, error)
}

type KeyStorage interface {
}

// Crypto TODO comment
type Crypto struct {
	keyRetriever EncryptionKeyRetriever
}

// NewCrypto initialize new signature usecase
func NewCrypto(keyRetriever EncryptionKeyRetriever) *Crypto {
	return &Crypto{
		keyRetriever: keyRetriever,
	}
}
