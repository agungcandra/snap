package database_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"github.com/agungcandra/snap/internal/repository/crypto/database"
)

func (s *EncryptionTestSuite) TestSign() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	s.Nil(err)

	stringToSign := "clientId=123456789|2024-12-08T17:00:00+07:00"

	s.Run("test_sign_string", func() {
		signature, err := s.svc.SignWithPrivateKey([]byte(stringToSign), privateKey)
		base64Encoded := base64.StdEncoding.EncodeToString(signature)
		s.Nil(err)
		s.NotEmpty(base64Encoded)

		err = s.svc.VerifyWithPublicKey(database.VerifyWithPublicKeyParams{
			Payload:   []byte(stringToSign),
			Signature: signature,
			PublicKey: &privateKey.PublicKey,
		})
		s.Nil(err)
	})

}
