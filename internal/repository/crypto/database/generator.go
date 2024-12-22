package database

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/agungcandra/snap/internal/repository/postgresql"
)

const (
	defaultPbkdf2Iteration = 100_000
	aes256KeyLength        = 32
)

type EncryptionKeyGenerationFunc func(name string) ([]byte, error)

type EncryptionKeyStorage struct {
	repository        EncryptionKeyRepository
	keyGenerationFunc EncryptionKeyGenerationFunc

	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewEncryptionKeyStorage(keyGenerationFn EncryptionKeyGenerationFunc, repository EncryptionKeyRepository, privateKey *rsa.PrivateKey) *EncryptionKeyStorage {
	return &EncryptionKeyStorage{
		repository:        repository,
		keyGenerationFunc: keyGenerationFn,
		privateKey:        privateKey,
		publicKey:         &privateKey.PublicKey,
	}
}

func (svc *EncryptionKeyStorage) GenerateKey(ctx context.Context, name string) ([]byte, error) {
	existingKey, err := svc.retrieveKey(ctx, name)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		return existingKey, nil
	}

	return svc.generateKey(ctx, name)
}

func (svc *EncryptionKeyStorage) RetrieveKey(ctx context.Context, name string) ([]byte, error) {
	return svc.retrieveKey(ctx, name)
}

func (svc *EncryptionKeyStorage) generateKey(ctx context.Context, name string) ([]byte, error) {
	plainKey, err := svc.keyGenerationFunc(name)
	if err != nil {
		return nil, err
	}

	cipherKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, svc.publicKey, plainKey, nil)
	if err != nil {
		return nil, err
	}

	if err = svc.repository.InsertKeyStorage(ctx, postgresql.InsertKeyStorageParams{
		Name: name,
		Data: cipherKey,
	}); err != nil {
		return nil, err
	}

	return plainKey, nil
}

func (svc *EncryptionKeyStorage) retrieveKey(ctx context.Context, name string) ([]byte, error) {
	keyStorage, err := svc.repository.FindLatestKeyStorageByName(ctx, name)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptOAEP(sha256.New(), rand.Reader, svc.privateKey, keyStorage.Data, nil)
}
