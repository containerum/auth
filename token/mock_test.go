package token

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"time"
)

func TestMockIssuerValidator(t *testing.T) {
	Convey("Test mock token issuer-validator", t, func() {
		mockiv := NewMockIssuerValidator(time.Hour)
		Convey("generate and validate tokens", func() {
			accessToken, err := mockiv.IssueAccessToken(ExtensionFields{})
			So(err, ShouldBeNil)
			So(accessToken.LifeTime, ShouldEqual, mockiv.returnedLifeTime)

			refreshToken, err := mockiv.IssueRefreshToken(ExtensionFields{})
			So(err, ShouldBeNil)
			So(refreshToken.LifeTime, ShouldEqual, mockiv.returnedLifeTime)

			valid, id, err := mockiv.ValidateToken(accessToken.Value)
			So(err, ShouldBeNil)
			So(id.Value, ShouldEqual, accessToken.Value)
			So(valid, ShouldBeTrue)

			valid, id, err = mockiv.ValidateToken(refreshToken.Value)
			So(err, ShouldBeNil)
			So(id.Value, ShouldEqual, refreshToken.Value)
			So(valid, ShouldBeTrue)
		})
		Convey("validate non-existing token", func() {
			valid, id, err := mockiv.ValidateToken("non-existing")
			So(err, ShouldBeNil)
			So(id, ShouldBeNil)
			So(valid, ShouldBeFalse)
		})
	})
}
