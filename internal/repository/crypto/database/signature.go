package database

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func (svc *Crypto) SignWithPrivateKey(payload []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}

type VerifyWithPublicKeyParams struct {
	Payload   []byte
	Signature []byte
	PublicKey *rsa.PublicKey
}

func (svc *Crypto) VerifyWithPublicKey(params VerifyWithPublicKeyParams) error {
	hashed := sha256.Sum256(params.Payload)
	return rsa.VerifyPKCS1v15(params.PublicKey, crypto.SHA256, hashed[:], params.Signature)
}
