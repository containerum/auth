package token

import (
	"crypto/rand"
	"testing"
	"time"

	"bitbucket.org/exonch/ch-grpc/auth"
	"github.com/dgrijalva/jwt-go"
	. "github.com/smartystreets/goconvey/convey"
)

func genKey() []byte {
	ret := make([]byte, 16)
	if _, err := rand.Read(ret); err != nil {
		panic(err)
	}
	return ret
}

var key = genKey()

var testValidatorConfig = JWTIssuerValidatorConfig{
	SigningMethod:        jwt.SigningMethodHS512,
	Issuer:               "test",
	AccessTokenLifeTime:  time.Hour * 2,
	RefreshTokenLifeTime: time.Hour * 48,
	SigningKey:           key,
	ValidationKey:        key,
}

var testExtensionFields = ExtensionFields{
	UserIDHash: "something",
	Role:       auth.Role_USER.String(),
}

func TestAccessToken(t *testing.T) {
	jwtiv := NewJWTIssuerValidator(testValidatorConfig)
	Convey("Generate and validate access token", t, func() {
		token, err := jwtiv.IssueAccessToken(ExtensionFields{})
		So(err, ShouldBeNil)
		So(token.LifeTime, ShouldEqual, testValidatorConfig.AccessTokenLifeTime)
		valid, err := jwtiv.ValidateToken(token.Value)
		So(err, ShouldBeNil)
		So(valid, ShouldBeTrue)
	})
}

func TestRefreshToken(t *testing.T) {
	jwtiv := NewJWTIssuerValidator(testValidatorConfig)
	Convey("Generate and validate refresh token", t, func() {
		token, err := jwtiv.IssueRefreshToken(testExtensionFields)
		So(err, ShouldBeNil)
		So(token.LifeTime, ShouldEqual, testValidatorConfig.RefreshTokenLifeTime)
		valid, err := jwtiv.ValidateToken(token.Value)
		So(err, ShouldBeNil)
		So(valid, ShouldBeTrue)
	})
}

func TestValidation(t *testing.T) {
	jwtiv := NewJWTIssuerValidator(testValidatorConfig)
	Convey("Test invalid token validation", t, func() {
		_, err := jwtiv.ValidateToken("not token")
		So(err, ShouldNotBeNil)
		valid, err := jwtiv.ValidateToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9." +
			"TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
		So(err.Error(), ShouldEqual, jwt.ErrSignatureInvalid.Error())
		So(valid, ShouldBeFalse)
	})
}
