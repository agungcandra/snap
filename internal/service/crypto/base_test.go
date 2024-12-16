package crypto_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"github.com/agungcandra/snap/internal/service/crypto"
	mock_database "github.com/agungcandra/snap/tests/mocks/pkg/database"
	mock_crypto "github.com/agungcandra/snap/tests/mocks/service/crypto"
)

type EncryptionTestSuite struct {
	suite.Suite

	ctx        context.Context
	ctrl       *gomock.Controller
	repository *mock_crypto.Mockrepository
	pool       *mock_database.MockPgxPool

	password   string
	privateKey *rsa.PrivateKey
	der        []byte

	svc *crypto.Crypto
}

func (s *EncryptionTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.password = "randomPassword"
	s.pool = mock_database.NewMockPgxPool(s.ctrl)
	s.repository = mock_crypto.NewMockrepository(s.ctrl)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Nil(err)
	s.privateKey = privateKey
	s.der = x509.MarshalPKCS1PrivateKey(s.privateKey)

	s.svc = crypto.NewCrypto(s.pool, s.repository)
}

func (s *EncryptionTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func TestSignatureTestSuite(t *testing.T) {
	suite.Run(t, new(EncryptionTestSuite))
}
