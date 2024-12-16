package crypto_test

import (
	"errors"

	"github.com/agungcandra/snap/internal/service/crypto"
)

func (s *EncryptionTestSuite) TestDecryptWith() {
	s.Run("invalid_keygen", func() {
		_, err := s.svc.DecryptWith(crypto.DecryptPayload{}, nil)
		s.ErrorIs(err, crypto.ErrInvalidKeyGeneration)
	})

	s.Run("error_generate_key", func() {
		_, err := s.svc.DecryptWith(crypto.DecryptPayload{}, func() ([]byte, error) {
			return nil, errors.New("internal server error")
		})

		s.EqualError(err, "internal server error")
	})

	s.Run("decrypt_with_invalid_key", func() {
		encryptOne, err := s.svc.Encrypt(s.der, crypto.RandGenerator(32))
		s.Nil(err)

		otherEncrypt, err := s.svc.Encrypt(s.der, crypto.RandGenerator(32))
		s.Nil(err)

		decrypted, err := s.svc.Decrypt(crypto.DecryptPayload{
			EncryptedPayload: encryptOne.Payload,
			Key:              otherEncrypt.Key,
			Nonce:            encryptOne.Nonce,
		})
		s.Nil(decrypted)
		s.EqualError(err, "failed to decrypt the key: cipher: message authentication failed")
	})
}
