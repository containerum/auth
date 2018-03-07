package routes

import (
	"net/http"

	"git.containerum.net/ch/auth/utils"
	"git.containerum.net/ch/grpc-proto-files/auth"
	umtypes "git.containerum.net/ch/json-types/user-manager"
	"git.containerum.net/ch/kube-client/pkg/cherry/adaptors/gonic"
	"git.containerum.net/ch/kube-client/pkg/cherry/auth"
	chutils "git.containerum.net/ch/utils"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

var srv auth.AuthServer

// SetupRoutes sets up router and services needed for server operation
func SetupRoutes(engine *gin.Engine, server auth.AuthServer) {
	srv = server

	token := engine.Group("/token")
	{
		// Create token
		token.POST("", chutils.RequireHeaders(
			autherr.ErrValidation,
			umtypes.UserAgentHeader,
			umtypes.FingerprintHeader,
			umtypes.UserIDHeader,
			umtypes.ClientIPHeader,
			umtypes.UserRoleHeader,
		), createTokenHandler)

		// Check token
		token.GET("/:access_token", chutils.RequireHeaders(
			autherr.ErrValidation,
			umtypes.UserAgentHeader,
			umtypes.FingerprintHeader,
			umtypes.ClientIPHeader,
		), checkTokenHandler)

		// Get user tokens
		token.GET("",
			chutils.RequireHeaders(autherr.ErrValidation, umtypes.UserIDHeader),
			getUserTokensHandler)

		// Extend token (refresh only)
		token.PUT("/:refresh_token",
			chutils.RequireHeaders(autherr.ErrValidation, umtypes.FingerprintHeader),
			extendTokenHandler)

		// Delete token by ID
		token.DELETE("/:token_id",
			chutils.RequireHeaders(autherr.ErrValidation, umtypes.UserIDHeader),
			deleteTokenByIDHandler)
	}

	user := engine.Group("/user")
	{
		// Delete user tokens
		user.DELETE("/:user_id/tokens", deleteUserTokensHandler)
	}
}

func createTokenHandler(ctx *gin.Context) {
	req := &auth.CreateTokenRequest{
		UserAgent:   chutils.MustGetUserAgent(ctx.Request.Context()),
		Fingerprint: chutils.MustGetFingerprint(ctx.Request.Context()),
		UserId:      utils.UUIDFromString(chutils.MustGetUserID(ctx.Request.Context())),
		UserIp:      chutils.MustGetClientIP(ctx.Request.Context()),
		UserRole:    chutils.MustGetUserRole(ctx.Request.Context()),
		PartTokenId: utils.UUIDFromString(chutils.MustGetPartTokenID(ctx.Request.Context())),
	}

	var access struct {
		Access *auth.ResourcesAccess `json:"access" binding:"required"`
	}

	if err := ctx.ShouldBindWith(&access, binding.JSON); err != nil {
		gonic.Gonic(autherr.ErrValidation().AddDetailsErr(err), ctx)
		return
	}

	req.Access = access.Access

	resp, err := srv.CreateToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func checkTokenHandler(ctx *gin.Context) {
	req := &auth.CheckTokenRequest{
		AccessToken: ctx.Param("access_token"),
		UserAgent:   chutils.MustGetUserAgent(ctx.Request.Context()),
		FingerPrint: chutils.MustGetFingerprint(ctx.Request.Context()),
		UserIp:      chutils.MustGetClientIP(ctx.Request.Context()),
	}

	resp, err := srv.CheckToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Set(umtypes.UserIDHeader, resp.GetUserId().GetValue())
	ctx.Set(umtypes.UserRoleHeader, resp.GetUserRole())
	ctx.Set(umtypes.TokenIDHeader, resp.GetTokenId().GetValue())
	if resp.PartTokenId != nil {
		ctx.Set(umtypes.PartTokenIDHeader, resp.GetPartTokenId().GetValue())
	}

	ctx.JSON(http.StatusOK, gin.H{
		"access": resp.GetAccess(),
	})
}

func extendTokenHandler(ctx *gin.Context) {
	req := &auth.ExtendTokenRequest{
		RefreshToken: ctx.Param("refresh_token"),
		Fingerprint:  chutils.MustGetFingerprint(ctx.Request.Context()),
	}

	resp, err := srv.ExtendToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func getUserTokensHandler(ctx *gin.Context) {
	req := &auth.GetUserTokensRequest{
		UserId: utils.UUIDFromString(chutils.MustGetUserID(ctx.Request.Context())),
	}

	resp, err := srv.GetUserTokens(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func deleteTokenByIDHandler(ctx *gin.Context) {
	req := &auth.DeleteTokenRequest{
		TokenId: utils.UUIDFromString(ctx.Param("token_id")),
		UserId:  utils.UUIDFromString(chutils.MustGetUserID(ctx.Request.Context())),
	}

	_, err := srv.DeleteToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Status(http.StatusOK)
}

func deleteUserTokensHandler(ctx *gin.Context) {
	req := &auth.DeleteUserTokensRequest{
		UserId: utils.UUIDFromString(ctx.Param("user_id")),
	}

	_, err := srv.DeleteUserTokens(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Status(http.StatusOK)
}
