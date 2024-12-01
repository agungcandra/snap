package signature

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultPbkdfIteration = 100_000
	defaultKeyLen         = 32
)

type signatureRepository interface {
}

type Signature struct {
	secretKey           string
	signatureRepository signatureRepository
}

func NewSignature(signatureRepository signatureRepository, secretKey string) Signature {
	return Signature{
		secretKey:           secretKey,
		signatureRepository: signatureRepository,
	}
}

func (svc *Signature) GenerateKey(salt []byte) []byte {
	return pbkdf2.Key([]byte(svc.secretKey), salt, defaultPbkdfIteration, defaultKeyLen, sha256.New)
}
