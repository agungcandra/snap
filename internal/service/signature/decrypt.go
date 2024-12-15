package signature

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Decrypt
func (svc *Signature) Decrypt(encrypted Encrypted, keygen KeyGenerationFn) ([]byte, error) {
	key, err := keygen()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	privateKey, err := aesGCM.Open(nil, encrypted.Nonce, encrypted.Payload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the key: %v", err)
	}

	return privateKey, err
}
