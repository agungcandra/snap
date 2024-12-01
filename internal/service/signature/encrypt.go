package signature

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

func (svc *Signature) EncryptKey(privateKey []byte, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	nonce := make([]byte, nonceSize)
	// Need to io.ReadFull when generate noonce to ensure that all nonce block is filled to ensure uniquness
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed generate nonce: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	cipherText := aesGCM.Seal(nil, nonce, privateKey, nil)
	return append(nonce, cipherText...), nil
}

func (svc *Signature) EncryptRSAKey(privateKey []byte) ([]byte, []byte, error) {
	salt := make([]byte, saltSize)
	// Use rand.Read is enough for generate salt
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	kek := svc.GenerateKey(salt)
	encryptedPrivateKey, err := svc.EncryptKey(privateKey, kek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt private key: %v", err)
	}

	return encryptedPrivateKey, salt, nil
}
