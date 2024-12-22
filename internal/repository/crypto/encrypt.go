package crypto

import (
	"context"
)

type Crypto interface {
	Encrypt(ctx context.Context, payload []byte)
	Decrypt(ctx context.Context)
}

type Encrypted struct {
	Payload []byte
	Key     []byte
	Nonce   []byte
	Salt    []byte
}

type EncryptRequest struct {
	Name      string
	PlainText []byte
}

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
