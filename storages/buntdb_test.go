package storages

import (
	"time"

	"context"
	"testing"

	"bitbucket.org/exonch/ch-auth/token"
	"bitbucket.org/exonch/ch-auth/utils"
	"bitbucket.org/exonch/ch-grpc/auth"
	. "github.com/smartystreets/goconvey/convey"
)

func initTestBuntDBStorage() *BuntDBStorage {
	testBuntDBStorage, err := NewBuntDBStorage(BuntDBStorageConfig{
		File:         ":memory:",
		TokenFactory: token.NewMockIssuerValidator(time.Hour),
	})
	if err != nil {
		panic(err)
	}
	return testBuntDBStorage
}

var testCreateTokenRequest = &auth.CreateTokenRequest{
	UserAgent:   "Mozilla/5.0 (X11; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0",
	Fingerprint: "myfingerprint",
	UserId:      utils.NewUUID(),
	UserIp:      "127.0.0.1",
	UserRole:    auth.Role_USER,
	RwAccess:    true,
	Access: &auth.ResourcesAccess{
		Namespace: []*auth.AccessObject{
			{
				Label:  "ns1",
				Id:     "ns1",
				Access: auth.AccessLevel_OWNER,
			},
		},
		Volume: []*auth.AccessObject{
			{
				Label:  "vol1",
				Id:     "vol1",
				Access: auth.AccessLevel_OWNER,
			},
		},
	},
	PartTokenId: utils.NewUUID(),
}

func TestBuntDBNormal(t *testing.T) {
	storage := initTestBuntDBStorage()

	Convey("Test storage functions in normal mode", t, func() {
		Convey("Check generated token", func() {
			issuedTokens, err := storage.CreateToken(context.Background(), testCreateTokenRequest)
			So(err, ShouldBeNil)
			So(issuedTokens, ShouldNotBeNil)
			Printf("\nGenerated issuedTokens: %v\n", issuedTokens)

			tvr, err := storage.CheckToken(context.Background(), &auth.CheckTokenRequest{
				AccessToken: issuedTokens.AccessToken,
				UserAgent:   testCreateTokenRequest.UserAgent,
				FingerPrint: testCreateTokenRequest.Fingerprint,
				UserIp:      testCreateTokenRequest.UserIp,
			})
			So(err, ShouldBeNil)
			So(tvr.PartTokenId, ShouldResemble, testCreateTokenRequest.PartTokenId)
			So(tvr.Access, ShouldResemble, testCreateTokenRequest.Access)
			So(tvr.UserRole, ShouldEqual, testCreateTokenRequest.UserRole)
			So(tvr.UserId, ShouldResemble, testCreateTokenRequest.UserId)
			So(tvr.TokenId, ShouldNotBeNil)

			_, err = storage.CheckToken(context.Background(), &auth.CheckTokenRequest{
				AccessToken: issuedTokens.RefreshToken,
				UserAgent:   testCreateTokenRequest.UserAgent,
				FingerPrint: testCreateTokenRequest.Fingerprint,
				UserIp:      testCreateTokenRequest.UserIp,
			})
			So(err, ShouldNotBeNil)

			Convey("Get user issuedTokens", func() {
				gtr, err := storage.GetUserTokens(context.Background(), &auth.GetUserTokensRequest{
					UserId: testCreateTokenRequest.UserId,
				})
				So(err, ShouldBeNil)
				So(gtr.Tokens, ShouldHaveLength, 1)
				So(gtr.Tokens[0].UserAgent, ShouldResemble, testCreateTokenRequest.UserAgent)
				So(gtr.Tokens[0].Ip, ShouldResemble, testCreateTokenRequest.UserIp)
			})
		})

		Convey("Check token extension", func() {
			issuedTokens, err := storage.CreateToken(context.Background(), testCreateTokenRequest)
			ter, err := storage.ExtendToken(context.Background(), &auth.ExtendTokenRequest{
				RefreshToken: issuedTokens.RefreshToken,
				Fingerprint:  testCreateTokenRequest.Fingerprint,
			})
			So(err, ShouldBeNil)
			So(ter.AccessToken, ShouldNotEqual, issuedTokens.AccessToken)
			So(ter.RefreshToken, ShouldNotEqual, issuedTokens.RefreshToken)

			Convey("Old tokens now should be invalid", func() {
				_, err := storage.CheckToken(context.Background(), &auth.CheckTokenRequest{
					AccessToken: issuedTokens.AccessToken,
					UserAgent:   testCreateTokenRequest.UserAgent,
					FingerPrint: testCreateTokenRequest.Fingerprint,
					UserIp:      testCreateTokenRequest.UserIp,
				})
				So(err, ShouldNotBeNil)
			})

			Convey("New tokens should ve valid", func() {
				tvr, err := storage.CheckToken(context.Background(), &auth.CheckTokenRequest{
					AccessToken: ter.AccessToken,
					UserAgent:   testCreateTokenRequest.UserAgent,
					FingerPrint: testCreateTokenRequest.Fingerprint,
					UserIp:      testCreateTokenRequest.UserIp,
				})
				So(err, ShouldBeNil)
				So(tvr.PartTokenId, ShouldResemble, testCreateTokenRequest.PartTokenId)
				So(tvr.Access, ShouldResemble, testCreateTokenRequest.Access)
				So(tvr.UserRole, ShouldEqual, testCreateTokenRequest.UserRole)
				So(tvr.UserId, ShouldResemble, testCreateTokenRequest.UserId)
				So(tvr.TokenId, ShouldNotBeNil)
				issuedTokens.AccessToken = ter.AccessToken
				issuedTokens.RefreshToken = ter.RefreshToken
			})

			Convey("Get user tokens", func() {
				gtr, err := storage.GetUserTokens(context.Background(), &auth.GetUserTokensRequest{
					UserId: testCreateTokenRequest.UserId,
				})
				So(err, ShouldBeNil)
				So(gtr.Tokens, ShouldHaveLength, 1)
				So(gtr.Tokens[0].UserAgent, ShouldResemble, testCreateTokenRequest.UserAgent)
				So(gtr.Tokens[0].Ip, ShouldResemble, testCreateTokenRequest.UserIp)
			})
		})

		Convey("Delete token by id", func() {
			issuedTokens, err := storage.CreateToken(context.Background(), testCreateTokenRequest)
			tvr, err := storage.CheckToken(context.Background(), &auth.CheckTokenRequest{
				AccessToken: issuedTokens.AccessToken,
				UserAgent:   testCreateTokenRequest.UserAgent,
				FingerPrint: testCreateTokenRequest.Fingerprint,
				UserIp:      testCreateTokenRequest.UserIp,
			})
			So(err, ShouldBeNil)

			_, err = storage.DeleteToken(context.Background(), &auth.DeleteTokenRequest{
				TokenId: tvr.TokenId,
				UserId:  tvr.UserId,
			})
			So(err, ShouldBeNil)

			gtr, err := storage.GetUserTokens(context.Background(), &auth.GetUserTokensRequest{
				UserId: tvr.UserId,
			})
			So(err, ShouldBeNil)
			So(gtr.Tokens, ShouldHaveLength, 0)
		})

		Convey("Delete token by user id", func() {
			issuedTokens, err := storage.CreateToken(context.Background(), testCreateTokenRequest)
			tvr, err := storage.CheckToken(context.Background(), &auth.CheckTokenRequest{
				AccessToken: issuedTokens.AccessToken,
				UserAgent:   testCreateTokenRequest.UserAgent,
				FingerPrint: testCreateTokenRequest.Fingerprint,
				UserIp:      testCreateTokenRequest.UserIp,
			})
			So(err, ShouldBeNil)

			_, err = storage.DeleteUserTokens(context.Background(), &auth.DeleteUserTokensRequest{
				UserId: tvr.UserId,
			})
			So(err, ShouldBeNil)

			gtr, err := storage.GetUserTokens(context.Background(), &auth.GetUserTokensRequest{
				UserId: tvr.UserId,
			})
			So(err, ShouldBeNil)
			So(gtr.Tokens, ShouldHaveLength, 0)
		})
	})

	Convey("Close storage", t, func() {
		So(storage.Close(), ShouldBeNil)
	})
}
