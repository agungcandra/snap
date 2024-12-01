package accesstoken

import "github.com/agungcandra/snap/internal/service/codes"

const (
	defaultExpiresIn = 900
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
	AccessToken    string
	TokenType      string
	ExpiresIn      int
	AdditionalInfo map[string]string
}

func (svc *AccessToken) BusinessToBusiness() {}
