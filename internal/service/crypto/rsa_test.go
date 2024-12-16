package crypto_test

import (
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/agungcandra/snap/internal/repository/postgresql"
	"github.com/agungcandra/snap/internal/service/crypto"
)

func (s *EncryptionTestSuite) TestSaveKey() {
	clientIDStr := uuid.NewString()
	var clientID pgtype.UUID
	_ = clientID.Scan(clientIDStr)
	var keyID int64 = 1001

	encryptedKey := crypto.Encrypted{
		Payload: []byte("randomEncryptedKey"),
		Salt:    []byte("randomSalt"),
		Nonce:   []byte("randomNonce"),
	}

	s.Run("success_save_key", func() {
		s.repository.EXPECT().InsertKey(s.ctx, postgresql.InsertKeyParams{
			ClientID:     clientID,
			EncryptedKey: encryptedKey.Payload,
		}).Return(keyID, nil)
		s.repository.EXPECT().InsertNonce(s.ctx, postgresql.InsertNonceParams{
			KeyID: keyID,
			Nonce: encryptedKey.Nonce,
		}).Return(nil)
		s.repository.EXPECT().InsertSalt(s.ctx, postgresql.InsertSaltParams{
			KeyID: keyID,
			Salt:  encryptedKey.Salt,
		}).Return(nil)

		err := s.svc.SaveKey(s.ctx, s.repository, clientIDStr, encryptedKey)
		s.Nil(err)
	})

	s.Run("failed_insert_key", func() {
		s.repository.EXPECT().InsertKey(s.ctx, postgresql.InsertKeyParams{
			ClientID:     clientID,
			EncryptedKey: encryptedKey.Payload,
		}).Return(keyID, errors.New("internal server error"))

		err := s.svc.SaveKey(s.ctx, s.repository, clientIDStr, encryptedKey)
		s.ErrorIs(err, crypto.ErrFailedInsertKey)
	})

	s.Run("failed_insert_nonce", func() {
		s.repository.EXPECT().InsertKey(s.ctx, postgresql.InsertKeyParams{
			ClientID:     clientID,
			EncryptedKey: encryptedKey.Payload,
		}).Return(keyID, nil)
		s.repository.EXPECT().InsertNonce(s.ctx, postgresql.InsertNonceParams{
			KeyID: keyID,
			Nonce: encryptedKey.Nonce,
		}).Return(errors.New("internal server error"))

		err := s.svc.SaveKey(s.ctx, s.repository, clientIDStr, encryptedKey)
		s.ErrorIs(err, crypto.ErrFailedInsertNonce)
	})

	s.Run("failed_insert_salt", func() {
		s.repository.EXPECT().InsertKey(s.ctx, postgresql.InsertKeyParams{
			ClientID:     clientID,
			EncryptedKey: encryptedKey.Payload,
		}).Return(keyID, nil)
		s.repository.EXPECT().InsertNonce(s.ctx, postgresql.InsertNonceParams{
			KeyID: keyID,
			Nonce: encryptedKey.Nonce,
		}).Return(nil)
		s.repository.EXPECT().InsertSalt(s.ctx, postgresql.InsertSaltParams{
			KeyID: keyID,
			Salt:  encryptedKey.Salt,
		}).Return(errors.New("internal server error"))

		err := s.svc.SaveKey(s.ctx, s.repository, clientIDStr, encryptedKey)
		s.ErrorIs(err, crypto.ErrFailedInsertSalt)
	})

	s.Run("invalid_client_id", func() {
		err := s.svc.SaveKey(s.ctx, s.repository, "randomClientID", encryptedKey)
		s.ErrorIs(err, crypto.ErrInvalidClientID)
	})
}
