package accesstoken

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"

	"github.com/agungcandra/snap/internal/repository/crypto"
	"github.com/agungcandra/snap/internal/repository/postgresql"
	"github.com/agungcandra/snap/internal/service/codes"
	"github.com/agungcandra/snap/pkg/logger"
)

const (
	grantTypeClientCredential = "client_credentials"

	tokenTypeBearer = "Bearer"
)

var (
	// TimeNow is helper function to generate current time
	TimeNow = time.Now
)

type BusinessToBusinessParams struct {
	Timestamp string
	ClientKey string
	Signature string

	GrantType      string
	AdditionalInfo map[string]string
}

type BusinessToBusinessResult struct {
	Timestamp string
	ClientKey string

	ResponseCode   codes.ResponseCode
	AccessToken    AccessTokenData
	AdditionalInfo map[string]string
}

func (svc *AccessToken) BusinessToBusiness(ctx context.Context, params BusinessToBusinessParams) (BusinessToBusinessResult, error) {
	if params.GrantType != grantTypeClientCredential {
		return BusinessToBusinessResult{}, ErrInvalidGrantType
	}

	if _, err := time.Parse(time.RFC3339Nano, params.Timestamp); err != nil {
		return BusinessToBusinessResult{}, ErrInvalidTimestamp
	}

	client, err := svc.repo.FindClientByID(ctx, params.ClientKey)
	if err != nil {
		logger.ErrorWithContext(ctx, err, zap.String("tag", "access_token.business_to_business"))
		return BusinessToBusinessResult{}, ErrInvalidClientKey
	}

	publicKey, err := svc.retrieveClientPublicKey(ctx, client)
	if err != nil {
		return BusinessToBusinessResult{}, err
	}

	var buf bytes.Buffer
	_, _ = buf.WriteString(fmt.Sprintf("%s|%s", params.ClientKey, params.Timestamp))
	digest := sha256.Sum256(buf.Bytes())

	signature, err := base64.StdEncoding.DecodeString(params.Signature)
	if err != nil {
		logger.ErrorWithContext(ctx, err, zap.String("tag", "access_token.business_to_business"))
		return BusinessToBusinessResult{}, ErrInvalidSignature
	}

	if err = rsa.VerifyPKCS1v15(publicKey, stdcrypto.SHA256, digest[:], signature); err != nil {
		logger.ErrorWithContext(ctx, err, zap.String("tag", "access_token.business_to_business"))
		return BusinessToBusinessResult{}, ErrInvalidSignature
	}

	token, err := svc.generateAccessToken(ctx, client)
	if err != nil {
		return BusinessToBusinessResult{}, err
	}

	return BusinessToBusinessResult{
		Timestamp: params.Timestamp,
		ClientKey: params.ClientKey,
		ResponseCode: codes.ResponseCode{
			Status: http.StatusOK,
		},
		AccessToken:    token,
		AdditionalInfo: params.AdditionalInfo,
	}, nil
}

func (svc *AccessToken) retrieveClientPublicKey(ctx context.Context, client postgresql.Client) (*rsa.PublicKey, error) {
	publicKeyRes, err := svc.cryptoProvider.Decrypt(ctx, crypto.DecryptRequest{
		Name:       client.ID,
		Ciphertext: client.PublicKey,
	})
	if err != nil {
		logger.ErrorWithContext(ctx, err, zap.String("tag", "access_token.retrieveClientPublicKey"))
		return nil, ErrInvalidParsePublicKey
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyRes.PlainText)
	if err != nil {
		logger.ErrorWithContext(ctx, err, zap.String("tag", "access_token.retrieveClientPublicKey"))
		return nil, ErrInvalidParsePublicKey
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrInvalidParsePublicKey
	}

	return rsaPublicKey, nil
}

func (svc *AccessToken) generateAccessToken(ctx context.Context, client postgresql.Client) (AccessTokenData, error) {
	now := TimeNow()
	expiredIn := now.Add(15 * time.Minute)
	claims := jwt.MapClaims{
		"sub": client.ID,
		"iat": now.Unix(),
		"exp": expiredIn.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(svc.hmacSecretKey)
	if err != nil {
		logger.ErrorWithContext(ctx, err, zap.String("tag", "access_token.generateAccessToken"))
		return AccessTokenData{}, ErrFailedGenerateToken
	}

	return AccessTokenData{
		Token:     tokenString,
		Type:      tokenTypeBearer,
		ExpiresIn: expiredIn,
	}, nil
}

type AccessTokenData struct {
	Token     string
	Type      string
	ExpiresIn time.Time
}
