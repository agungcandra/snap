package database

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize = 16
)

// Pbkdf2Generator key generation function pbkdf2 for derived key from password
func Pbkdf2Generator(name string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	plainKey := pbkdf2.Key([]byte(name), salt, defaultPbkdf2Iteration, aes256KeyLength, sha256.New)
	return plainKey, nil
}
