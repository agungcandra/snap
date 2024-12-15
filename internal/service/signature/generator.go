package signature

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultPbkdf2Iteration = 100_000
	aes256KeyLength        = 32
)

// Pbkdf2Generator key generator using pbkdf2 that derive key from password, salt and iteration count
func Pbkdf2Generator(password string, salt []byte) KeyGenerationFn {
	return func() ([]byte, error) {
		key := pbkdf2.Key([]byte(password), salt, defaultPbkdf2Iteration, aes256KeyLength, sha256.New)
		return key, nil
	}
}

// RandGenerator random key generator using crypto random to securely generate random key
func RandGenerator(keyLen int) KeyGenerationFn {
	return func() ([]byte, error) {
		key := make([]byte, keyLen)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}

		return key, nil
	}
}
