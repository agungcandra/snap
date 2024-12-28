package accesstoken

import (
	"context"

	"github.com/agungcandra/snap/internal/repository/crypto"
	"github.com/agungcandra/snap/internal/repository/postgresql"
)

type accessTokenRepository interface {
	FindClientByID(ctx context.Context, id string) (postgresql.Client, error)
	InsertClient(ctx context.Context, arg postgresql.InsertClientParams) (postgresql.Client, error)
}

// AccessToken implement logic related to access token, including client creation,
type AccessToken struct {
	repo           accessTokenRepository
	cryptoProvider crypto.Crypto

	hmacSecretKey []byte
}

func NewAccessToken(repo accessTokenRepository, cryptoProvider crypto.Crypto, hmacSecret string) *AccessToken {
	return &AccessToken{
		repo:           repo,
		cryptoProvider: cryptoProvider,
		hmacSecretKey:  []byte(hmacSecret),
	}
}
