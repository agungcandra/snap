package database_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/agungcandra/snap/internal/repository/crypto/database"
	"io"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	mock_crypto "github.com/agungcandra/snap/tests/mocks/repository/crypto/database"
)

type EncryptionTestSuite struct {
	suite.Suite

	ctx          context.Context
	ctrl         *gomock.Controller
	keyRetriever *mock_crypto.MockEncryptionKeyRetriever

	sampleKey  []byte
	privateKey *rsa.PrivateKey
	der        []byte

	svc *database.Crypto
}

func (s *EncryptionTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.keyRetriever = mock_crypto.NewMockEncryptionKeyRetriever(s.ctrl)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Nil(err)
	s.privateKey = privateKey
	s.der = x509.MarshalPKCS1PrivateKey(s.privateKey)

	s.sampleKey = make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, s.sampleKey)

	s.svc = database.NewCrypto(s.keyRetriever)
}

func (s *EncryptionTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func TestSignatureTestSuite(t *testing.T) {
	suite.Run(t, new(EncryptionTestSuite))
}
