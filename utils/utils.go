package utils

import (
	"encoding/base64"
	"encoding/json"

	"bitbucket.org/exonch/ch-grpc/auth"
	"bitbucket.org/exonch/ch-grpc/common"
)

// ShortUserAgent generates short user agent from normal user agent using base64
func ShortUserAgent(userAgent string) string {
	return base64.StdEncoding.EncodeToString([]byte(userAgent))
}

func EncodeAccessObjects(req []*auth.AccessObject) string {
	ret, _ := json.Marshal(req)
	return base64.StdEncoding.EncodeToString(ret)
}

func RequestToRecord(req *auth.CreateTokenRequest, tokenId *common.UUID) *auth.StoredToken {
	return &auth.StoredToken{
		TokenId:       tokenId,
		UserAgent:     req.UserAgent,
		Platform:      ShortUserAgent(req.UserAgent),
		Fingerprint:   req.Fingerprint,
		UserId:        req.UserId,
		UserRole:      req.UserRole,
		UserNamespace: EncodeAccessObjects(req.Access.Namespace),
		UserVolume:    EncodeAccessObjects(req.Access.Volume),
		RwAccess:      req.RwAccess,
		UserIp:        req.UserIp,
	}
}
