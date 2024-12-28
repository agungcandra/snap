package accesstoken_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	accesstoken "github.com/agungcandra/snap/internal/service/access_token"
	mock_crypto "github.com/agungcandra/snap/tests/mocks/repository/crypto"
	mock_accesstoken "github.com/agungcandra/snap/tests/mocks/service/access_token"
)

type AccessTokenTestSuite struct {
	suite.Suite

	ctrl           *gomock.Controller
	ctx            context.Context
	repo           *mock_accesstoken.MockaccessTokenRepository
	cryptoProvider *mock_crypto.MockCrypto
	sampleUUID     string
	hmacSecret     []byte

	svc *accesstoken.AccessToken
}

func (s *AccessTokenTestSuite) SetupSuite() {
	s.ctrl = gomock.NewController(s.T())

	s.ctx = context.Background()
	s.repo = mock_accesstoken.NewMockaccessTokenRepository(s.ctrl)
	s.cryptoProvider = mock_crypto.NewMockCrypto(s.ctrl)
	s.sampleUUID = uuid.NewString()
	s.hmacSecret = []byte("super-secret-key")

	accesstoken.NewClientKeyGenerator = func() string {
		return s.sampleUUID
	}

	s.svc = accesstoken.NewAccessToken(s.repo, s.cryptoProvider, string(s.hmacSecret))
}

func (s *AccessTokenTestSuite) TearDownSuite() {
	s.ctrl.Finish()
}

func TestAccessTokenTestSuite(t *testing.T) {
	suite.Run(t, new(AccessTokenTestSuite))
}
