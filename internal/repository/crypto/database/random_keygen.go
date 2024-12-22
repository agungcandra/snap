package database

import (
	"crypto/rand"
	"io"
)

// RandomGenerator key generation function using rand crypto
func RandomGenerator(keyLen int) EncryptionKeyGenerationFunc {
	return func(_ string) ([]byte, error) {
		plainKey := make([]byte, keyLen)
		if _, err := io.ReadFull(rand.Reader, plainKey); err != nil {
			return nil, err
		}

		return plainKey, nil
	}
}
