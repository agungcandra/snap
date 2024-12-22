package database_test

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/agungcandra/snap/internal/repository/crypto"
)

func (s *EncryptionTestSuite) TestDecrypt() {
	encryptRequest := crypto.EncryptRequest{
		Name:      "client-one",
		PlainText: s.der,
	}
	keyOne := make([]byte, 32)
	keyTwo := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, keyOne)
	_, _ = io.ReadFull(rand.Reader, keyTwo)

	s.keyRetriever.EXPECT().GenerateKey(s.ctx, encryptRequest.Name).Return(keyOne, nil)

	encryptOne, err := s.svc.Encrypt(s.ctx, encryptRequest)
	s.Nil(err)

	decryptRequest := crypto.DecryptRequest(encryptOne)

	s.Run("success", func() {
		s.keyRetriever.EXPECT().RetrieveKey(s.ctx, encryptOne.Name).Return(keyOne, nil)

		result, err := s.svc.Decrypt(s.ctx, decryptRequest)
		s.Nil(err)
		s.Equal(s.der, result.PlainText)
	})

	s.Run("failed_retrieve_key", func() {
		s.keyRetriever.EXPECT().RetrieveKey(s.ctx, encryptOne.Name).Return(nil, errors.New("internal server error"))

		result, err := s.svc.Decrypt(s.ctx, decryptRequest)
		s.Empty(result)
		s.EqualError(err, "internal server error")
	})

	s.Run("invalid_size", func() {
		s.keyRetriever.EXPECT().RetrieveKey(s.ctx, encryptOne.Name).Return(keyOne, nil)

		result, err := s.svc.Decrypt(s.ctx, crypto.DecryptRequest{
			Name:       encryptOne.Name,
			Ciphertext: []byte("abc"),
		})
		s.Empty(result)
		s.EqualError(err, "payload size is too short")
	})

	s.Run("decrypt_with_invalid_key", func() {
		s.keyRetriever.EXPECT().RetrieveKey(s.ctx, encryptOne.Name).Return(keyTwo, nil)

		result, err := s.svc.Decrypt(s.ctx, decryptRequest)
		s.Empty(result)
		s.EqualError(err, "failed to decrypt the key: cipher: message authentication failed")
	})
}
