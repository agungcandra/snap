package accesstoken

import (
	"context"

	"github.com/agungcandra/snap/internal/service/codes"
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

func (svc *AccessToken) BusinessToBusiness(ctx context.Context, params BusinessToBusinessParams) (BusinessToBusinessResult, error) {

	return BusinessToBusinessResult{}, nil
}
