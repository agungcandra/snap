package database_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"github.com/agungcandra/snap/internal/repository/crypto/database"
	"github.com/agungcandra/snap/internal/repository/postgresql"
	mock_database "github.com/agungcandra/snap/tests/mocks/repository/crypto/database"
)

func (s *EncryptionKeyStorageTestSuite) TestGenerateKey() {
	s.Run("success_generate_new_key", func() {
		s.repository.EXPECT().FindLatestKeyStorageByName(s.ctx, "key1").
			Return(postgresql.KeyStorage{}, pgx.ErrNoRows)
		s.repository.EXPECT().InsertKeyStorage(s.ctx, gomock.Any()).DoAndReturn(
			func(_ context.Context, params postgresql.InsertKeyStorageParams) error {
				plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.privateKey, params.Data, nil)
				s.Nil(err)
				s.Equal("key1-sample", string(plain))
				return nil
			},
		)

		result, err := s.svc.GenerateKey(s.ctx, "key1")
		s.Equal("key1-sample", string(result))
		s.Nil(err)
	})

	s.Run("success_retrieve_existing_key", func() {
		s.repository.EXPECT().FindLatestKeyStorageByName(s.ctx, "key1").
			Return(postgresql.KeyStorage{
				ID:      1,
				Name:    "key1",
				Version: 1,
				Data:    s.encryptedSample,
			}, nil)

		result, err := s.svc.GenerateKey(s.ctx, "key1")
		s.Equal("key1-sample", string(result))
		s.Nil(err)
	})

	s.Run("invalid_key_for_decrypt", func() {
		newPrivateKey, _ := rsa.GenerateKey(rand.Reader, 1024)

		svc := database.NewEncryptionKeyStorage(staticKeyGenerationFunc, s.repository, newPrivateKey)
		s.repository.EXPECT().FindLatestKeyStorageByName(s.ctx, "key1").
			Return(postgresql.KeyStorage{
				ID:      1,
				Name:    "key1",
				Version: 1,
				Data:    s.encryptedSample,
			}, nil)

		result, err := svc.GenerateKey(s.ctx, "key1")
		s.Empty(result)
		s.EqualError(err, "crypto/rsa: decryption error")
	})

	s.Run("retrieve_key_error", func() {
		s.repository.EXPECT().FindLatestKeyStorageByName(s.ctx, "key1").
			Return(postgresql.KeyStorage{}, errors.New("internal server error"))

		result, err := s.svc.GenerateKey(s.ctx, "key1")
		s.Empty(result)
		s.EqualError(err, "internal server error")
	})

	s.Run("failed_to_save_key", func() {
		s.repository.EXPECT().FindLatestKeyStorageByName(s.ctx, "key1").
			Return(postgresql.KeyStorage{}, pgx.ErrNoRows)
		s.repository.EXPECT().InsertKeyStorage(s.ctx, gomock.Any()).
			Return(errors.New("internal server error"))

		result, err := s.svc.GenerateKey(s.ctx, "key1")
		s.Empty(result)
		s.EqualError(err, "internal server error")
	})
}

func (s *EncryptionKeyStorageTestSuite) TestRetrieveKey() {
	s.Run("success", func() {
		s.repository.EXPECT().FindLatestKeyStorageByName(s.ctx, "key1").
			Return(postgresql.KeyStorage{
				ID:      1,
				Name:    "key1",
				Version: 1,
				Data:    s.encryptedSample,
			}, nil)

		result, err := s.svc.RetrieveKey(s.ctx, "key1")
		s.Equal("key1-sample", string(result))
		s.Nil(err)
	})

	s.Run("error_find_key", func() {
		s.repository.EXPECT().FindLatestKeyStorageByName(s.ctx, "key1").
			Return(postgresql.KeyStorage{}, errors.New("internal server error"))

		result, err := s.svc.RetrieveKey(s.ctx, "key1")
		s.Empty(result)
		s.EqualError(err, "internal server error")
	})

	s.Run("failed_to_decrypt", func() {
		newPrivateKey, _ := rsa.GenerateKey(rand.Reader, 1024)

		svc := database.NewEncryptionKeyStorage(staticKeyGenerationFunc, s.repository, newPrivateKey)
		s.repository.EXPECT().FindLatestKeyStorageByName(s.ctx, "key1").
			Return(postgresql.KeyStorage{
				ID:      1,
				Name:    "key1",
				Version: 1,
				Data:    s.encryptedSample,
			}, nil)

		result, err := svc.RetrieveKey(s.ctx, "key1")
		s.Empty(result)
		s.EqualError(err, "crypto/rsa: decryption error")
	})

}

func staticKeyGenerationFunc(name string) ([]byte, error) {
	switch {
	case strings.HasPrefix(name, "error"):
		return nil, errors.New(name)
	case strings.HasPrefix(name, "key"):
		return []byte(fmt.Sprintf("%s-sample", name)), nil
	default:
		return []byte("invalid key"), nil
	}
}

type EncryptionKeyStorageTestSuite struct {
	suite.Suite

	ctrl *gomock.Controller

	ctx        context.Context
	repository *mock_database.MockEncryptionKeyRepository
	privateKey *rsa.PrivateKey

	encryptedSample []byte

	svc *database.EncryptionKeyStorage
}

func (s *EncryptionKeyStorageTestSuite) SetupSuite() {
	s.ctrl = gomock.NewController(s.T())
	s.ctx = context.Background()
	s.repository = mock_database.NewMockEncryptionKeyRepository(s.ctrl)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Nil(err)
	s.privateKey = privateKey

	encryptedSample, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, []byte("key1-sample"), nil)
	s.encryptedSample = encryptedSample

	s.svc = database.NewEncryptionKeyStorage(staticKeyGenerationFunc, s.repository, s.privateKey)
}

func (s *EncryptionKeyStorageTestSuite) TearDownSuite() {
	s.ctrl.Finish()
}

func TestEncryptionKeyStorageTestSuite(t *testing.T) {
	suite.Run(t, new(EncryptionKeyStorageTestSuite))
}

//func BenchmarkPbkdf2Generator(b *testing.B) {
//	salt := make([]byte, 32)
//	_, _ = io.ReadFull(rand.Reader, salt)
//
//	fn := database.Pbkdf2Generator("randomPasswordGenerator", salt)
//
//	for i := 0; i < b.N; i++ {
//		_, _ = fn()
//	}
//}
//
//func TestPbkdf2Generator(t *testing.T) {
//	salt := make([]byte, 32)
//	_, _ = io.ReadFull(rand.Reader, salt)
//
//	otherSalt := make([]byte, 32)
//	_, _ = io.ReadFull(rand.Reader, salt)
//
//	t.Run("simplePassword", func(t *testing.T) {
//		key, err := database.Pbkdf2Generator("lowEntropyKey", salt)()
//		assert.Nil(t, err)
//		assert.Len(t, key, 32)
//
//		otherKey, err := database.Pbkdf2Generator("lowEntropyKey", otherSalt)()
//		assert.Nil(t, err)
//		assert.Len(t, otherKey, 32)
//
//		assert.NotEqual(t, key, otherKey)
//	})
//
//	t.Run("highEntropyPassword", func(t *testing.T) {
//		password := "thisIsPasswordWithHighLevelOfEntropyBecauseItsSizeIsSoLongThatIHavingHardTimeToComeUpWithMessage"
//
//		key, err := database.Pbkdf2Generator(password, salt)()
//		assert.Nil(t, err)
//		assert.Len(t, key, 32)
//
//		otherKey, err := database.Pbkdf2Generator(password, otherSalt)()
//		assert.Nil(t, err)
//		assert.Len(t, key, 32)
//
//		// different salt should generate different key, regardless password length
//		assert.NotEqual(t, key, otherKey)
//	})
//}
//
//
//func BenchmarkRandGenerator(b *testing.B) {
//	fn := database.RandGenerator(32)
//	for i := 0; i < b.N; i++ {
//		_, _ = fn()
//	}
//}
