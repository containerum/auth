package utils

import (
	"encoding/base64"

	"crypto/rand"
	"fmt"

	"strings"

	"git.containerum.net/ch/auth/proto"
	"github.com/mssola/user_agent"
)

// ShortUserAgent generates short user agent from normal user agent using base64
func ShortUserAgent(userAgent string) string {
	ua := user_agent.New(userAgent)
	platform := ua.Platform()
	engine, _ := ua.Engine()
	os := ua.OS()
	browser, _ := ua.Browser()
	toEncode := strings.Join([]string{platform, os, engine, browser}, " ")
	return base64.StdEncoding.EncodeToString([]byte(toEncode))
}

// NewUUID generates a new UUID
func NewUUID() *authProto.UUID {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		fmt.Println("Error: ", err)
		return nil
	}

	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10

	return &authProto.UUID{
		Value: fmt.Sprintf("%X-%X-%X-%X-%X", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]),
	}
}

// UUIDEquals checks if provided UUIDs are equal
func UUIDEquals(a, b *authProto.UUID) bool {
	return a == b || a != nil && b != nil && a.Value == b.Value
}

// UUIDFromString returns UUID object parsed from string
func UUIDFromString(value string) *authProto.UUID {
	return &authProto.UUID{
		Value: strings.ToLower(value),
	}
}
