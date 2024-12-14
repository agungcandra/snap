package signature_test

import (
	"errors"
	"github.com/agungcandra/snap/internal/repository/postgresql"
	"github.com/agungcandra/snap/internal/service/signature"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func (s *SignatureTestSuite) TestSaveKey() {
	clientIDStr := uuid.NewString()
	var clientID pgtype.UUID
	_ = clientID.Scan(clientIDStr)
	var keyID int64 = 1001

	encryptedKey := signature.EncryptedKey{
		EncryptedKey: []byte("randomEncryptedKey"),
		Salt:         []byte("randomSalt"),
		Nonce:        []byte("randomNonce"),
	}

	s.Run("success_save_key", func() {
		s.repository.EXPECT().InsertKey(s.ctx, postgresql.InsertKeyParams{
			ClientID:     clientID,
			EncryptedKey: encryptedKey.EncryptedKey,
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
			EncryptedKey: encryptedKey.EncryptedKey,
		}).Return(keyID, errors.New("internal server error"))

		err := s.svc.SaveKey(s.ctx, s.repository, clientIDStr, encryptedKey)
		s.ErrorIs(err, signature.ErrFailedInsertKey)
	})

	s.Run("failed_insert_nonce", func() {
		s.repository.EXPECT().InsertKey(s.ctx, postgresql.InsertKeyParams{
			ClientID:     clientID,
			EncryptedKey: encryptedKey.EncryptedKey,
		}).Return(keyID, nil)
		s.repository.EXPECT().InsertNonce(s.ctx, postgresql.InsertNonceParams{
			KeyID: keyID,
			Nonce: encryptedKey.Nonce,
		}).Return(errors.New("internal server error"))

		err := s.svc.SaveKey(s.ctx, s.repository, clientIDStr, encryptedKey)
		s.ErrorIs(err, signature.ErrFailedInsertNonce)
	})

	s.Run("failed_insert_salt", func() {
		s.repository.EXPECT().InsertKey(s.ctx, postgresql.InsertKeyParams{
			ClientID:     clientID,
			EncryptedKey: encryptedKey.EncryptedKey,
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
		s.ErrorIs(err, signature.ErrFailedInsertSalt)
	})

	s.Run("invalid_client_id", func() {
		err := s.svc.SaveKey(s.ctx, s.repository, "randomClientID", encryptedKey)
		s.ErrorIs(err, signature.ErrInvalidClientID)
	})
}
