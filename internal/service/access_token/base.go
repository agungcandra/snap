package accesstoken

import (
	"context"

	"github.com/agungcandra/snap/internal/repository/crypto"
	"github.com/agungcandra/snap/internal/repository/postgresql"
)

type accessTokenRepository interface {
	InsertClient(ctx context.Context, arg postgresql.InsertClientParams) (postgresql.Client, error)
}

// AccessToken implement logic related to access token, including client creation,
type AccessToken struct {
	repo           accessTokenRepository
	cryptoProvider crypto.Crypto
}

func NewAccessToken(repo accessTokenRepository, cryptoProvider crypto.Crypto) *AccessToken {
	return &AccessToken{
		repo:           repo,
		cryptoProvider: cryptoProvider,
	}
}
