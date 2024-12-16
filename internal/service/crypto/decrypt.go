package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type DecryptPayload struct {
	EncryptedPayload []byte
	Key              []byte
	Nonce            []byte
}

func (svc *Crypto) Decrypt(payload DecryptPayload) ([]byte, error) {
	return svc.decrypt(payload)
}

func (svc *Crypto) DecryptWith(payload DecryptPayload, keygen KeyGenerationFn) ([]byte, error) {
	if keygen == nil {
		return nil, ErrInvalidKeyGeneration
	}

	key, err := keygen()
	if err != nil {
		return nil, err
	}

	payload.Key = key
	return svc.decrypt(payload)
}

func (svc *Crypto) decrypt(payload DecryptPayload) ([]byte, error) {
	block, err := aes.NewCipher(payload.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	decryptedData, err := aesGCM.Open(nil, payload.Nonce, payload.EncryptedPayload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the key: %v", err)
	}

	return decryptedData, err
}
