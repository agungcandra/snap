package signature_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/agungcandra/snap/internal/service/signature"
	"github.com/stretchr/testify/assert"
)

func TestEncryptKey(t *testing.T) {
	sampleRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(sampleRSAKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})

	block, rest := pem.Decode(privateKeyPEM)
	assert.Empty(t, rest)
	assert.Equal(t, privateKeyBytes, block.Bytes)

	signature := signature.NewSignature(nil, "randomSignaturePassword")
	encrypted, salt, err := signature.EncryptRSAKey(privateKeyPEM)
	assert.Nil(t, err)

	decrypted, err := signature.DecryptRSAKey(encrypted, salt)
	assert.Nil(t, err)

	assert.Equal(t, privateKeyPEM, decrypted)
}
