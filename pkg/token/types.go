package token

import (
	"time"

	"git.containerum.net/ch/auth/pkg/utils"
	"git.containerum.net/ch/auth/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
)

// Kind is a token kind (see OAuth 2 standards). According to standard it can be only KindAccess and KindRefresh.
type Kind int

const (
	// KindAccess represents access token
	KindAccess Kind = iota

	// KindRefresh represents refresh token
	KindRefresh
)

// ExtensionFields is an advanced fields included to JWT
type ExtensionFields struct {
	UserIDHash  string `json:"user_id,omitempty"`
	Role        string `json:"role,omitempty"`
	PartTokenID string `json:"part_token_id,omitempty"`
}

// IssuedToken describes a token
type IssuedToken struct {
	Value    string
	ID       string
	IssuedAt time.Time
	LifeTime time.Duration
}

// Issuer is interface for creating access and refresh tokens.
type Issuer interface {
	IssueTokens(extensionFields ExtensionFields) (accessToken, refreshToken *IssuedToken, err error)
}

// ValidationResult describes token validation result.
type ValidationResult struct {
	Valid bool
	ID    string
	Kind  Kind
}

// Validator is interface for validating tokens
type Validator interface {
	ValidateToken(token string) (result *ValidationResult, err error)
}

// IssuerValidator is an interface for token factory
type IssuerValidator interface {
	Issuer
	Validator
	AccessFromRefresh(refreshToken string) (accessToken *IssuedToken, err error)
	Now() time.Time
}

// RequestToRecord prepares a value to store in database
func RequestToRecord(req *authProto.CreateTokenRequest, token *IssuedToken) *authProto.StoredToken {
	ret := &authProto.StoredToken{
		UserAgent:       req.GetUserAgent(),
		Platform:        utils.ShortUserAgent(req.GetUserAgent()),
		Fingerprint:     req.GetFingerprint(),
		UserId:          req.GetUserId(),
		UserRole:        req.GetUserRole(),
		UserIp:          req.GetUserIp(),
		LifeTime:        ptypes.DurationProto(token.LifeTime),
		RawRefreshToken: token.Value,
	}
	if token != nil {
		ret.TokenId = token.ID
	}
	if ts, err := ptypes.TimestampProto(token.IssuedAt); err != nil {
		logrus.WithError(err).Error("ptypes.TimestampProto() failed")
	} else {
		ret.CreatedAt = ts
	}
	return ret
}
