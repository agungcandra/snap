package crypto_test

import (
	"errors"

	"github.com/agungcandra/snap/internal/service/crypto"
)

func (s *EncryptionTestSuite) TestEncrypt() {
	s.Run("success", func() {
		encrypted, err := s.svc.Encrypt(s.der, crypto.RandGenerator(32))
		s.Nil(err)

		decrypted, err := s.svc.Decrypt(crypto.DecryptPayload{
			EncryptedPayload: encrypted.Payload,
			Key:              encrypted.Key,
			Nonce:            encrypted.Nonce,
		})
		s.Nil(err)

		s.Equal(decrypted, s.der)
	})

	s.Run("invalid_algorithm", func() {
		_, err := s.svc.Encrypt(s.der, nil)
		s.ErrorIs(err, crypto.ErrInvalidKeyGeneration)
	})

	s.Run("error_keygen", func() {
		_, err := s.svc.Encrypt(s.der, func() ([]byte, error) {
			return nil, errors.New("internal server error")
		})

		s.EqualError(err, "internal server error")
	})

	s.Run("invalid key", func() {
		_, err := s.svc.Encrypt(s.der, func() ([]byte, error) {
			return []byte("hel"), nil
		})

		s.EqualError(err, "failed to encrypt private key: failed to create AES cipher: crypto/aes: invalid key size 3")
	})
}

func (s *EncryptionTestSuite) TestEncryptWithPassword() {
	s.Run("success", func() {
		encrypted, err := s.svc.EncryptWithPassword(s.der, s.password)
		s.Nil(err)

		decrypted, err := s.svc.DecryptWith(crypto.DecryptPayload{
			EncryptedPayload: encrypted.Payload,
			Nonce:            encrypted.Nonce,
		}, crypto.Pbkdf2Generator(s.password, encrypted.Salt))
		s.Nil(err)

		s.Equal(decrypted, s.der)
	})
}
