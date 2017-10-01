package token

import (
	"time"

	"bitbucket.org/exonch/ch-grpc/common"
)

type ExtensionFields struct {
	UserIDHash string `json:"userID"`
	Role       string `json:"role"`
}

// Issuer is interface for creating access and refresh tokens.
type Issuer interface {
	IssueAccessToken(ExtensionFields) (token string, id *common.UUID, lifeTime time.Duration, err error)
	IssueRefreshToken(ExtensionFields) (token string, id *common.UUID, lifeTime time.Duration, err error)
}

// Validator is interface for validating tokens
type Validator interface {
	ValidateToken(token string, fields ExtensionFields) (bool, error)
}

type IssuerValidator interface {
	Issuer
	Validator
}
