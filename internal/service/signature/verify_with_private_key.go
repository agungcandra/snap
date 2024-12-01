package signature

import "context"

type VerifyWithPrivateKeyParams struct {
	ClientID  string
	Signature string
	Payload   string
}

func (svc *Signature) VerifyWithPrivateKey(ctx context.Context, params VerifyWithPrivateKeyParams) error {
	return nil
}
