package database_test

import (
	"errors"
	"github.com/agungcandra/snap/internal/repository/crypto"
)

func (s *EncryptionTestSuite) TestEncrypt() {
	req := crypto.EncryptRequest{
		Name:      "sample-data",
		PlainText: s.der,
	}
	s.Run("success", func() {
		s.keyRetriever.EXPECT().GenerateKey(s.ctx, req.Name).Return(s.sampleKey, nil)

		encrypted, err := s.svc.Encrypt(s.ctx, req)
		s.Nil(err)
		s.NotEmpty(encrypted)

		s.keyRetriever.EXPECT().RetrieveKey(s.ctx, req.Name).Return(s.sampleKey, nil)

		plain, err := s.svc.Decrypt(s.ctx, crypto.DecryptRequest{
			Name:       req.Name,
			Ciphertext: encrypted.Ciphertext,
		})
		s.Nil(err)
		s.Equal(req.PlainText, plain.PlainText)
	})

	s.Run("error_keygen", func() {
		s.keyRetriever.EXPECT().GenerateKey(s.ctx, req.Name).Return(nil, errors.New("internal server error"))
		_, err := s.svc.Encrypt(s.ctx, req)

		s.EqualError(err, "internal server error")
	})

	s.Run("invalid key", func() {
		s.keyRetriever.EXPECT().GenerateKey(s.ctx, req.Name).Return([]byte("invalid key"), nil)
		_, err := s.svc.Encrypt(s.ctx, req)

		s.EqualError(err, "failed to encrypt private key: failed to create AES cipher: crypto/aes: invalid key size 11")
	})
}
