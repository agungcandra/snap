package database

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/agungcandra/snap/internal/repository/crypto"
)

func (svc *Crypto) Decrypt(ctx context.Context, req crypto.DecryptRequest) (crypto.DecryptResponse, error) {
	key, err := svc.keyRetriever.RetrieveKey(ctx, req.Name)
	if err != nil {
		return crypto.DecryptResponse{}, err
	}

	plainText, err := svc.decrypt(req.Ciphertext, key)
	if err != nil {
		return crypto.DecryptResponse{}, err
	}

	return crypto.DecryptResponse{
		Name:      req.Name,
		PlainText: plainText,
	}, nil
}

func (svc *Crypto) decrypt(payload, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(payload) < nonceSize {
		return nil, errors.New("payload size is too short")
	}

	nonce, cipherText := payload[:nonceSize], payload[nonceSize:]
	decryptedData, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the key: %v", err)
	}

	return decryptedData, err
}
