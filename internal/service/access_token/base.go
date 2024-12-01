package accesstoken

type accessTokenRepository interface {
}

type AccessToken struct {
	repo accessTokenRepository
}

func NewAccessToken(repo accessTokenRepository) *AccessToken {
	return &AccessToken{}
}
