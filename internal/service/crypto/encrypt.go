package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	nonceSize = 12
	saltSize  = 16
)

// Encrypted represent encrypted payload with details related salt and nonce
type Encrypted struct {
	Payload []byte
	Key     []byte
	Nonce   []byte
	Salt    []byte
}

type KeyGenerationFn func() ([]byte, error)

func (svc *Crypto) Encrypt(payload []byte, keygen KeyGenerationFn) (Encrypted, error) {
	if keygen == nil {
		return Encrypted{}, ErrInvalidKeyGeneration
	}

	key, err := keygen()
	if err != nil {
		return Encrypted{}, err
	}

	encryptedPayload, nonce, err := svc.encrypt(payload, key)
	if err != nil {
		return Encrypted{}, fmt.Errorf("failed to encrypt private key: %v", err)
	}

	return Encrypted{
		Payload: encryptedPayload,
		Key:     key,
		Nonce:   nonce,
	}, nil
}

func (svc *Crypto) EncryptWithPassword(payload []byte, password string) (Encrypted, error) {
	salt := make([]byte, saltSize)
	// Use rand.Read is enough for generate salt
	if _, err := rand.Read(salt); err != nil {
		return Encrypted{}, fmt.Errorf("failed to generate salt: %v", err)
	}

	encrypted, err := svc.Encrypt(payload, Pbkdf2Generator(password, salt))
	if err != nil {
		return Encrypted{}, nil
	}

	encrypted.Salt = salt
	return encrypted, nil
}

func (svc *Crypto) encrypt(payload []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	nonce := make([]byte, nonceSize)
	// Need to io.ReadFull when generate noonce to ensure that all nonce block is filled to ensure uniquness
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed generate nonce: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	cipherText := aesGCM.Seal(nil, nonce, payload, nil)
	return cipherText, nonce, nil
}
