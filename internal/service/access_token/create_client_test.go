package accesstoken_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/agungcandra/snap/internal/repository/crypto"
	"github.com/agungcandra/snap/internal/repository/postgresql"
	accesstoken "github.com/agungcandra/snap/internal/service/access_token"
)

func (s *AccessTokenTestSuite) TestCreateClient() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Nil(err)

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	s.Nil(err)

	params := accesstoken.CreateClientParams{
		Name:      "new-client",
		PublicKey: publicKeyDER,
	}
	encryptedKey := []byte("sample-encrypted-key")

	client := postgresql.Client{
		ID:        s.sampleUUID,
		Name:      params.Name,
		PublicKey: encryptedKey,
	}

	s.Run("success", func() {
		s.cryptoProvider.EXPECT().Encrypt(s.ctx, crypto.EncryptRequest{
			Name:      s.sampleUUID,
			PlainText: params.PublicKey,
		}).Return(crypto.EncryptResponse{
			Name:       params.Name,
			Ciphertext: encryptedKey,
		}, nil)
		s.repo.EXPECT().InsertClient(s.ctx, postgresql.InsertClientParams{
			ID:        s.sampleUUID,
			Name:      params.Name,
			PublicKey: encryptedKey,
		}).Return(client, nil)

		result, err := s.svc.CreateClient(s.ctx, params)
		s.Nil(err)
		s.Equal(result, client)
	})

	s.Run("invalid_type", func() {
		ecdsaPrivateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ecdsaPublicKeyDER, _ := x509.MarshalPKIXPublicKey(&ecdsaPrivateKey.PublicKey)

		invalidParams := accesstoken.CreateClientParams{
			Name:      "invalid-client",
			PublicKey: ecdsaPublicKeyDER,
		}

		result, err := s.svc.CreateClient(s.ctx, invalidParams)
		s.Empty(result)
		s.ErrorIs(err, accesstoken.ErrInvalidParsePublicKey)
	})

	s.Run("failed_parse_public_key", func() {
		result, err := s.svc.CreateClient(s.ctx, accesstoken.CreateClientParams{
			Name:      params.Name,
			PublicKey: []byte("invalid-public-key"),
		})
		s.Empty(result)
		s.ErrorIs(err, accesstoken.ErrInvalidParsePublicKey)
	})

	s.Run("failed_encrypt_key", func() {
		s.cryptoProvider.EXPECT().Encrypt(s.ctx, crypto.EncryptRequest{
			Name:      s.sampleUUID,
			PlainText: params.PublicKey,
		}).Return(crypto.EncryptResponse{}, errors.New("internal error"))

		result, err := s.svc.CreateClient(s.ctx, params)
		s.Empty(result)
		s.EqualError(err, "internal error")
	})

	s.Run("failed_insert_client", func() {
		s.cryptoProvider.EXPECT().Encrypt(s.ctx, crypto.EncryptRequest{
			Name:      s.sampleUUID,
			PlainText: params.PublicKey,
		}).Return(crypto.EncryptResponse{
			Name:       params.Name,
			Ciphertext: encryptedKey,
		}, nil)
		s.repo.EXPECT().InsertClient(s.ctx, postgresql.InsertClientParams{
			ID:        s.sampleUUID,
			Name:      params.Name,
			PublicKey: encryptedKey,
		}).Return(postgresql.Client{}, errors.New("internal server error"))

		result, err := s.svc.CreateClient(s.ctx, params)
		s.Empty(result)
		s.ErrorIs(err, accesstoken.ErrFailedCreateClient)
	})
}
