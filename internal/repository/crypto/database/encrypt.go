package database

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/agungcandra/snap/internal/repository/crypto"
	"io"
)

func (svc *Crypto) Encrypt(ctx context.Context, req crypto.EncryptRequest) (crypto.EncryptResponse, error) {
	key, err := svc.keyRetriever.GenerateKey(ctx, req.Name)
	if err != nil {
		return crypto.EncryptResponse{}, err
	}

	encryptedPayload, err := svc.encrypt(req.PlainText, key)
	if err != nil {
		return crypto.EncryptResponse{}, fmt.Errorf("failed to encrypt private key: %v", err)
	}

	return crypto.EncryptResponse{
		Name:       req.Name,
		Ciphertext: encryptedPayload,
	}, nil
}

func (svc *Crypto) encrypt(plainText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	// Need to io.ReadFull when generate noonce to ensure that all nonce block is filled to ensure uniquness
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed generate nonce: %v", err)
	}

	cipherText := aesGCM.Seal(nil, nonce, plainText, nil)
	result := append(nonce, cipherText...)
	return result, nil
}
