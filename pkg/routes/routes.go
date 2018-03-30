package routes

import (
	"net/http"

	"git.containerum.net/ch/auth/proto"
	umtypes "git.containerum.net/ch/json-types/user-manager"
	"git.containerum.net/ch/kube-client/pkg/cherry/adaptors/gonic"
	"git.containerum.net/ch/kube-client/pkg/cherry/auth"
	chutils "git.containerum.net/ch/utils"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

var srv authProto.AuthServer

// SetupRoutes sets up router and services needed for server operation
func SetupRoutes(engine *gin.Engine, server authProto.AuthServer) {
	srv = server

	engine.Use(chutils.PrepareContext)

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

		// Get access token by ID
		token.GET("/:token_id",
			chutils.RequireHeaders(autherr.ErrValidation, umtypes.UserRoleHeader),
			getAccessTokenByIDHandler,
		)

	}

	user := engine.Group("/user")
	{
		// Delete user tokens
		user.DELETE("/:user_id/tokens", deleteUserTokensHandler)
	}
}

func createTokenHandler(ctx *gin.Context) {
	req := &authProto.CreateTokenRequest{
		UserAgent:   chutils.MustGetUserAgent(ctx.Request.Context()),
		Fingerprint: chutils.MustGetFingerprint(ctx.Request.Context()),
		UserId:      chutils.MustGetUserID(ctx.Request.Context()),
		UserIp:      chutils.MustGetClientIP(ctx.Request.Context()),
		UserRole:    chutils.MustGetUserRole(ctx.Request.Context()),
	}
	ptID, ptIDExist := chutils.GetPartTokenID(ctx.Request.Context())
	if ptIDExist {
		req.PartTokenId = ptID
	}

	var access struct {
		Access *authProto.ResourcesAccess `json:"access" binding:"required"`
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
	req := &authProto.CheckTokenRequest{
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

	ctx.Set(umtypes.UserIDHeader, resp.GetUserId())
	ctx.Set(umtypes.UserRoleHeader, resp.GetUserRole())
	ctx.Set(umtypes.TokenIDHeader, resp.GetTokenId())
	if resp.PartTokenId != "" {
		ctx.Set(umtypes.PartTokenIDHeader, resp.GetPartTokenId())
	}

	ctx.JSON(http.StatusOK, gin.H{
		"access": resp.GetAccess(),
	})
}

func extendTokenHandler(ctx *gin.Context) {
	req := &authProto.ExtendTokenRequest{
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
	req := &authProto.GetUserTokensRequest{
		UserId: chutils.MustGetUserID(ctx.Request.Context()),
	}

	resp, err := srv.GetUserTokens(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func deleteTokenByIDHandler(ctx *gin.Context) {
	req := &authProto.DeleteTokenRequest{
		TokenId: ctx.Param("token_id"),
		UserId:  chutils.MustGetUserID(ctx.Request.Context()),
	}

	_, err := srv.DeleteToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Status(http.StatusOK)
}

func deleteUserTokensHandler(ctx *gin.Context) {
	req := &authProto.DeleteUserTokensRequest{
		UserId: ctx.Param("user_id"),
	}

	_, err := srv.DeleteUserTokens(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Status(http.StatusOK)
}

func getAccessTokenByIDHandler(ctx *gin.Context) {
	req := &authProto.AccessTokenByIDRequest{
		TokenId: ctx.Param("token_id"),
	}

	resp, err := srv.AccessTokenByID(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}
