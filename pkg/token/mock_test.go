package token

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestMockIssuerValidator(t *testing.T) {
	Convey("Test mock token issuer-validator", t, func() {
		mockiv := NewMockIssuerValidator(time.Hour)
		Convey("generate and validate tokens", func() {
			accessToken, refreshToken, err := mockiv.IssueTokens(ExtensionFields{})
			So(err, ShouldBeNil)
			So(accessToken.LifeTime, ShouldEqual, mockiv.(*mockIssuerValidator).returnedLifeTime)
			So(refreshToken.LifeTime, ShouldEqual, mockiv.(*mockIssuerValidator).returnedLifeTime)
			So(accessToken.ID, ShouldResemble, refreshToken.ID)

			valid, err := mockiv.ValidateToken(accessToken.Value)
			So(err, ShouldBeNil)
			So(valid.ID, ShouldResemble, accessToken.ID)
			So(valid.Valid, ShouldBeTrue)
			So(valid.Kind, ShouldEqual, KindAccess)

			valid, err = mockiv.ValidateToken(refreshToken.Value)
			So(err, ShouldBeNil)
			So(valid.ID, ShouldResemble, refreshToken.ID)
			So(valid.Valid, ShouldBeTrue)
			So(valid.Kind, ShouldEqual, KindRefresh)
		})
		Convey("validate invalid token", func() {
			_, err := mockiv.ValidateToken("invalid")
			So(err, ShouldNotBeNil)
		})
		Convey("reconstruct access token from refresh", func() {
			accessToken, refreshToken, err := mockiv.IssueTokens(ExtensionFields{})
			So(err, ShouldBeNil)

			// because we losing nanoseconds
			accessToken.IssuedAt = accessToken.IssuedAt.Truncate(time.Second)

			reconstructedAccessToken, err := mockiv.AccessFromRefresh(refreshToken.Value)
			So(err, ShouldBeNil)

			So(reconstructedAccessToken, ShouldResemble, accessToken)

			valid, err := mockiv.ValidateToken(reconstructedAccessToken.Value)
			So(err, ShouldBeNil)
			So(valid, ShouldResemble, &ValidationResult{ID: accessToken.ID, Valid: true, Kind: KindAccess})
		})
	})
}
