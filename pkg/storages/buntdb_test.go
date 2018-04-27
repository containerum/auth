package storages

import (
	"time"

	"context"
	"testing"

	"os"

	"git.containerum.net/ch/auth/pkg/errors"
	"git.containerum.net/ch/auth/pkg/token"
	"git.containerum.net/ch/auth/pkg/utils"
	"git.containerum.net/ch/auth/proto"
	"github.com/containerum/cherry"
	"github.com/sirupsen/logrus"
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

func TestMain(m *testing.M) {
	if os.Getenv("TEST_DEBUG") != "" {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.PanicLevel)
	}
	os.Exit(m.Run())
}

var testCreateTokenRequest = &authProto.CreateTokenRequest{
	UserAgent:   "Mozilla/5.0 (X11; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0",
	Fingerprint: "myfingerprint",
	UserId:      utils.NewUUID(),
	UserIp:      "127.0.0.1",
	UserRole:    "user",
	RwAccess:    true,
	Access: &authProto.ResourcesAccess{
		Namespace: []*authProto.AccessObject{
			{
				Label:  "ns1",
				Id:     "ns1",
				Access: "owner",
			},
		},
		Volume: []*authProto.AccessObject{
			{
				Label:  "vol1",
				Id:     "vol1",
				Access: "owner",
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
			logrus.Debugf("\nGenerated issuedTokens: %v\n", issuedTokens)

			tvr, err := storage.CheckToken(context.Background(), &authProto.CheckTokenRequest{
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

			_, err = storage.CheckToken(context.Background(), &authProto.CheckTokenRequest{
				AccessToken: issuedTokens.RefreshToken,
				UserAgent:   testCreateTokenRequest.UserAgent,
				FingerPrint: testCreateTokenRequest.Fingerprint,
				UserIp:      testCreateTokenRequest.UserIp,
			})
			So(err, ShouldNotBeNil)

			Convey("Get user issuedTokens", func() {
				gtr, err := storage.GetUserTokens(context.Background(), &authProto.GetUserTokensRequest{
					UserId: testCreateTokenRequest.UserId,
				})
				So(err, ShouldBeNil)
				So(gtr.Tokens, ShouldHaveLength, 1)
				So(gtr.Tokens[0].UserAgent, ShouldResemble, testCreateTokenRequest.UserAgent)
				So(gtr.Tokens[0].Ip, ShouldResemble, testCreateTokenRequest.UserIp)
			})
		})

		Convey("Check token extension", func() {
			issuedTokens, createErr := storage.CreateToken(context.Background(), testCreateTokenRequest)
			So(createErr, ShouldBeNil)
			ter, storageErr := storage.ExtendToken(context.Background(), &authProto.ExtendTokenRequest{
				RefreshToken: issuedTokens.RefreshToken,
				Fingerprint:  testCreateTokenRequest.Fingerprint,
			})
			So(storageErr, ShouldBeNil)
			So(ter.AccessToken, ShouldNotEqual, issuedTokens.AccessToken)
			So(ter.RefreshToken, ShouldNotEqual, issuedTokens.RefreshToken)

			Convey("Old tokens should not be valid for refreshing", func() {
				_, err := storage.ExtendToken(context.Background(), &authProto.ExtendTokenRequest{
					RefreshToken: issuedTokens.RefreshToken,
					Fingerprint:  testCreateTokenRequest.Fingerprint,
				})
				So(err.(*cherry.Err).ID, ShouldResemble, autherr.ErrTokenNotFound().ID)
			})

			Convey("Old tokens now should be invalid", func() {
				_, err := storage.CheckToken(context.Background(), &authProto.CheckTokenRequest{
					AccessToken: issuedTokens.AccessToken,
					UserAgent:   testCreateTokenRequest.UserAgent,
					FingerPrint: testCreateTokenRequest.Fingerprint,
					UserIp:      testCreateTokenRequest.UserIp,
				})
				So(err, ShouldNotBeNil)
			})

			Convey("New tokens should ve valid", func() {
				tvr, err := storage.CheckToken(context.Background(), &authProto.CheckTokenRequest{
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
				gtr, err := storage.GetUserTokens(context.Background(), &authProto.GetUserTokensRequest{
					UserId: testCreateTokenRequest.UserId,
				})
				So(err, ShouldBeNil)
				So(gtr.Tokens, ShouldHaveLength, 1)
				So(gtr.Tokens[0].UserAgent, ShouldResemble, testCreateTokenRequest.UserAgent)
				So(gtr.Tokens[0].Ip, ShouldResemble, testCreateTokenRequest.UserIp)
			})
		})

		Convey("Delete token by id", func() {
			issuedTokens, createErr := storage.CreateToken(context.Background(), testCreateTokenRequest)
			So(createErr, ShouldBeNil)
			tvr, checkErr := storage.CheckToken(context.Background(), &authProto.CheckTokenRequest{
				AccessToken: issuedTokens.AccessToken,
				UserAgent:   testCreateTokenRequest.UserAgent,
				FingerPrint: testCreateTokenRequest.Fingerprint,
				UserIp:      testCreateTokenRequest.UserIp,
			})
			So(checkErr, ShouldBeNil)

			_, deleteErr := storage.DeleteToken(context.Background(), &authProto.DeleteTokenRequest{
				TokenId: tvr.TokenId,
				UserId:  tvr.UserId,
			})
			So(deleteErr, ShouldBeNil)

			gtr, getErr := storage.GetUserTokens(context.Background(), &authProto.GetUserTokensRequest{
				UserId: tvr.UserId,
			})
			So(getErr, ShouldBeNil)
			So(gtr.Tokens, ShouldHaveLength, 0)
		})

		Convey("Delete token by user id", func() {
			issuedTokens, createErr := storage.CreateToken(context.Background(), testCreateTokenRequest)
			So(createErr, ShouldBeNil)
			tvr, checkErr := storage.CheckToken(context.Background(), &authProto.CheckTokenRequest{
				AccessToken: issuedTokens.AccessToken,
				UserAgent:   testCreateTokenRequest.UserAgent,
				FingerPrint: testCreateTokenRequest.Fingerprint,
				UserIp:      testCreateTokenRequest.UserIp,
			})
			So(checkErr, ShouldBeNil)

			_, deleteErr := storage.DeleteUserTokens(context.Background(), &authProto.DeleteUserTokensRequest{
				UserId: tvr.UserId,
			})
			So(deleteErr, ShouldBeNil)

			gtr, getErr := storage.GetUserTokens(context.Background(), &authProto.GetUserTokensRequest{
				UserId: tvr.UserId,
			})
			So(getErr, ShouldBeNil)
			So(gtr.Tokens, ShouldHaveLength, 0)
		})

		Convey("Update resources access in token", func() {
			issuedTokens, createErr := storage.CreateToken(context.Background(), testCreateTokenRequest)
			So(createErr, ShouldBeNil)
			tvr, checkErr := storage.CheckToken(context.Background(), &authProto.CheckTokenRequest{
				AccessToken: issuedTokens.AccessToken,
				UserAgent:   testCreateTokenRequest.UserAgent,
				FingerPrint: testCreateTokenRequest.Fingerprint,
				UserIp:      testCreateTokenRequest.UserIp,
			})
			So(checkErr, ShouldBeNil)
			So(tvr.Access, ShouldResemble, testCreateTokenRequest.Access)

			newAccesses := &authProto.ResourcesAccess{
				Namespace: []*authProto.AccessObject{
					{Label: "a", Id: utils.NewUUID(), Access: "owner"},
				},
				Volume: []*authProto.AccessObject{
					{Label: "b", Id: utils.NewUUID(), Access: "owner"},
				},
			}

			_, updErr := storage.UpdateAccess(context.Background(), &authProto.UpdateAccessRequest{
				Users: []*authProto.UpdateAccessRequestElement{
					{UserId: testCreateTokenRequest.UserId, Access: newAccesses},
				},
			})
			So(updErr, ShouldBeNil)
			tvr, checkErr = storage.CheckToken(context.Background(), &authProto.CheckTokenRequest{
				AccessToken: issuedTokens.AccessToken,
				UserAgent:   testCreateTokenRequest.UserAgent,
				FingerPrint: testCreateTokenRequest.Fingerprint,
				UserIp:      testCreateTokenRequest.UserIp,
			})
			So(checkErr, ShouldBeNil)
			So(tvr.Access, ShouldResemble, newAccesses)
		})
	})

	Convey("Close storage", t, func() {
		So(storage.Close(), ShouldBeNil)
	})
}

func TestBuntDBExtra(t *testing.T) {
	storage := initTestBuntDBStorage()

	Convey("Test storage functions in bad-data mode", t, func() {
		Convey("Check non-existing and invalid token", func() {
			_, err := storage.CheckToken(context.Background(), &authProto.CheckTokenRequest{
				AccessToken: "not-token",
				UserAgent:   "lol",
				FingerPrint: "kek",
				UserIp:      "127.0.0.1",
			})
			So(err.(*cherry.Err).ID.Kind, ShouldEqual, autherr.ErrInvalidToken().ID.Kind)
		})

		Convey("Extend non-extendable token", func() {
			issuedTokens, err := storage.CreateToken(context.Background(), testCreateTokenRequest)
			So(err, ShouldBeNil)
			So(issuedTokens, ShouldNotBeNil)

			_, err = storage.ExtendToken(context.Background(), &authProto.ExtendTokenRequest{
				RefreshToken: issuedTokens.AccessToken,
				Fingerprint:  testCreateTokenRequest.Fingerprint,
			})
			So(err, ShouldNotBeNil)

			_, err = storage.ExtendToken(context.Background(), &authProto.ExtendTokenRequest{
				RefreshToken: "not-token",
				Fingerprint:  testCreateTokenRequest.Fingerprint,
			})
			So(err.(*cherry.Err).ID.Kind, ShouldEqual, autherr.ErrInvalidToken().ID.Kind)
		})

		Convey("Delete non-existing and not owned token", func() {
			issuedTokens, err := storage.CreateToken(context.Background(), testCreateTokenRequest)
			So(err, ShouldBeNil)
			So(issuedTokens, ShouldNotBeNil)

			_, err = storage.DeleteToken(context.Background(), &authProto.DeleteTokenRequest{
				TokenId: utils.NewUUID(),
				UserId:  testCreateTokenRequest.UserId,
			})
			So(err, ShouldNotBeNil)

			// acquire token id
			tvr, err := storage.CheckToken(context.Background(), &authProto.CheckTokenRequest{
				AccessToken: issuedTokens.AccessToken,
				UserAgent:   testCreateTokenRequest.UserAgent,
				FingerPrint: testCreateTokenRequest.Fingerprint,
				UserIp:      testCreateTokenRequest.UserIp,
			})
			So(err, ShouldBeNil)

			_, err = storage.DeleteToken(context.Background(), &authProto.DeleteTokenRequest{
				TokenId: tvr.TokenId,
				UserId:  utils.NewUUID(),
			})
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Close storage", t, func() {
		So(storage.Close(), ShouldBeNil)
	})
}
