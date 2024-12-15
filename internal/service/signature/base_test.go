package signature_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"github.com/agungcandra/snap/internal/service/signature"
	mock_database "github.com/agungcandra/snap/tests/mocks/pkg/database"
	mock_signature "github.com/agungcandra/snap/tests/mocks/service/signature"
)

type SignatureTestSuite struct {
	suite.Suite

	ctx        context.Context
	ctrl       *gomock.Controller
	repository *mock_signature.Mockrepository
	pool       *mock_database.MockPgxPool

	secretKey string

	svc *signature.Signature
}

func (s *SignatureTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.secretKey = "secret"
	s.pool = mock_database.NewMockPgxPool(s.ctrl)
	s.repository = mock_signature.NewMockrepository(s.ctrl)

	s.svc = signature.NewSignature(s.pool, s.repository)
}

func (s *SignatureTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func TestSignatureTestSuite(t *testing.T) {
	suite.Run(t, new(SignatureTestSuite))
}
