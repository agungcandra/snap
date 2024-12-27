package crypto

import (
	"context"
)

// Crypto define cryptography function for encrypt, and decrypt related function
type Crypto interface {
	Encrypt(ctx context.Context, req EncryptRequest) (EncryptResponse, error)
	Decrypt(ctx context.Context, req DecryptRequest) (DecryptResponse, error)
}

// EncryptRequest request for encryption plain data based on name
type EncryptRequest struct {
	Name      string
	PlainText []byte
}

// EncryptResponse struct for response data from encryption request based on name
type EncryptResponse struct {
	Name       string
	Ciphertext []byte
}

type DecryptRequest struct {
	Name       string
	Ciphertext []byte
}

type DecryptResponse struct {
	Name      string
	PlainText []byte
}
