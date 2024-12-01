package signature

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func (svc *Signature) DecryptKey(encryptedKey []byte, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	nonce := encryptedKey[:nonceSize]
	cipherText := encryptedKey[nonceSize:]

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	privateKey, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the key: %v", err)
	}

	return privateKey, err
}

func (svc *Signature) DecryptRSAKey(encryptedKey []byte, salt []byte) ([]byte, error) {
	kek := svc.GenerateKey(salt)

	privateKey, err := svc.DecryptKey(encryptedKey, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}

	return privateKey, nil
}
