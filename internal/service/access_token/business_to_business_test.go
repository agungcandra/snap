package accesstoken_test

import (
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/agungcandra/snap/internal/repository/crypto"
	"github.com/agungcandra/snap/internal/repository/postgresql"
	accesstoken "github.com/agungcandra/snap/internal/service/access_token"
)

func (s *AccessTokenTestSuite) TestBusinessToBusiness() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Nil(err)

	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	s.Nil(err)

	tt, _ := time.Parse(time.RFC3339Nano, "2024-01-01T00:00:00.000Z")

	accesstoken.TimeNow = func() time.Time {
		return tt
	}

	xClientKey := "sample-client"
	xTimestamp := tt.Format(time.RFC3339Nano)
	stringToSign := fmt.Sprintf("%s|%s", xClientKey, xTimestamp)
	digest := sha256.Sum256([]byte(stringToSign))

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, stdcrypto.SHA256, digest[:])
	s.Nil(err)

	encodedSignature := base64.StdEncoding.EncodeToString(signature)

	params := accesstoken.BusinessToBusinessParams{
		Timestamp: xTimestamp,
		ClientKey: xClientKey,
		Signature: encodedSignature,
		GrantType: "client_credentials",
	}

	client := postgresql.Client{
		ID:        xClientKey,
		Name:      "Sample Client Unit Testing",
		PublicKey: publicKey,
	}

	s.Run("success", func() {
		s.repo.EXPECT().FindClientByID(s.ctx, params.ClientKey).
			Return(client, nil)
		s.cryptoProvider.EXPECT().Decrypt(s.ctx, crypto.DecryptRequest{
			Name:       xClientKey,
			Ciphertext: publicKey,
		}).Return(crypto.DecryptResponse{
			Name:      xClientKey,
			PlainText: publicKey,
		}, nil)
		result, err := s.svc.BusinessToBusiness(s.ctx, params)
		s.Nil(err)
		s.NotEmpty(result)
	})
}
