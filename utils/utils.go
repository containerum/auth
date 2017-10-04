package utils

import (
	"encoding/base64"

	"crypto/rand"
	"fmt"

	"bitbucket.org/exonch/ch-grpc/common"
)

// ShortUserAgent generates short user agent from normal user agent using base64
func ShortUserAgent(userAgent string) string {
	return base64.StdEncoding.EncodeToString([]byte(userAgent))
}

func NewUUID() *common.UUID {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		return nil
	}

	return &common.UUID{
		Value: fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]),
	}
}

func UUIDEquals(a, b *common.UUID) bool {
	return a != nil && b != nil && a.Value == b.Value
}
