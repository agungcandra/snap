package accesstoken

import "github.com/agungcandra/snap/internal/service/codes"

var (
	ErrInvalidParsePublicKey = codes.ErrorResponseCode{
		Status:      0,
		ServiceCode: 0,
		CaseCode:    0,
	}

	ErrFailedGenerateClientID = codes.ErrorResponseCode{
		Status:      0,
		ServiceCode: 0,
		CaseCode:    0,
	}

	ErrFailedCreateClient = codes.ErrorResponseCode{
		Status:      0,
		ServiceCode: 0,
		CaseCode:    0,
	}
)
