package token

import (
	"encoding/base64"
	"time"

	"github.com/json-iterator/go"

	"git.containerum.net/ch/auth/utils"
	"git.containerum.net/ch/grpc-proto-files/auth"
	"git.containerum.net/ch/grpc-proto-files/common"
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
	ID       *common.UUID
	LifeTime time.Duration
}

// Issuer is interface for creating access and refresh tokens.
type Issuer interface {
	IssueTokens(extensionFields ExtensionFields) (accessToken, refreshToken *IssuedToken, err error)
}

// ValidationResult describes token validation result.
type ValidationResult struct {
	Valid bool
	ID    *common.UUID
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
}

// EncodeAccessObjects encodes resource access objects to store in database
func EncodeAccessObjects(req []*auth.AccessObject) string {
	if req == nil {
		return ""
	}
	ret, err := jsoniter.Marshal(req)
	if err != nil {
		logrus.WithError(err).Error("encode access objects failed")
	}
	return base64.StdEncoding.EncodeToString(ret)
}

// DecodeAccessObjects decodes resource access object from database record
func DecodeAccessObjects(value string) (ret []*auth.AccessObject) {
	if len(value) >= 2 {
		if value[0] == '\x00' {
			value = string(value[1:])
		}
	} else {
		return make([]*auth.AccessObject, 0)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		logrus.WithError(err).Error("decode access objects failed")
		return make([]*auth.AccessObject, 0)
	}
	err = jsoniter.Unmarshal(decoded, &ret)
	if err != nil {
		logrus.WithError(err).Error("decode access objects failed")
		return make([]*auth.AccessObject, 0)
	}
	return
}

// RequestToRecord prepares a value to store in database
func RequestToRecord(req *auth.CreateTokenRequest, token *IssuedToken) *auth.StoredToken {
	ret := &auth.StoredToken{
		UserAgent:     req.GetUserAgent(),
		Platform:      utils.ShortUserAgent(req.GetUserAgent()),
		Fingerprint:   req.GetFingerprint(),
		UserId:        req.GetUserId(),
		UserRole:      req.GetUserRole(),
		UserNamespace: EncodeAccessObjects(req.GetAccess().GetNamespace()),
		UserVolume:    EncodeAccessObjects(req.GetAccess().GetVolume()),
		RwAccess:      req.GetRwAccess(),
		UserIp:        req.GetUserIp(),
		PartTokenId:   req.GetPartTokenId(),
	}
	if token != nil {
		ret.TokenId = token.ID
	}
	return ret
}
