package routes

import (
	"net/http"

	"git.containerum.net/ch/auth/utils"
	"git.containerum.net/ch/grpc-proto-files/auth"
	"git.containerum.net/ch/json-types/errors"
	umtypes "git.containerum.net/ch/json-types/user-manager"
	"github.com/gin-gonic/gin"
)

var srv auth.AuthServer

// SetupRoutes sets up router and services needed for server operation
func SetupRoutes(engine *gin.Engine, server auth.AuthServer) {
	srv = server

	group := engine.Group("/token")

	// Create token
	group.POST("", requireHeaders(
		umtypes.UserAgentHeader,
		umtypes.FingerprintHeader,
		umtypes.UserIDHeader,
		umtypes.ClientIPHeader,
		umtypes.UserRoleHeader,
	), validateHeaders, createTokenHandler)

	// Check token
	group.GET("/:access_token", requireHeaders(
		umtypes.UserAgentHeader,
		umtypes.FingerprintHeader,
		umtypes.ClientIPHeader,
	), validateHeaders, checkTokenHandler)

	// Extend token (refresh only)
	group.PUT("/:refresh_token", requireHeaders(umtypes.FingerprintHeader), validateHeaders, extendTokenHandler)

	// Get user tokens
	group.GET("", requireHeaders(umtypes.UserIDHeader), validateHeaders, getUserTokensHandler)

	// Delete token by ID
	group.DELETE("/:token_id", requireHeaders(umtypes.UserIDHeader),
		validateHeaders,
		validateURLParam("token_id", "uuid4"),
		deleteTokenByIDHandler)

	// Delete user tokens
	group.DELETE("/user", deleteUserTokensHandler)
}

func createTokenHandler(ctx *gin.Context) {
	req := &auth.CreateTokenRequest{
		UserAgent:   ctx.GetHeader(umtypes.UserAgentHeader),
		Fingerprint: ctx.GetHeader(umtypes.FingerprintHeader),
		UserId:      utils.UUIDFromString(ctx.GetHeader(umtypes.UserIDHeader)),
		UserIp:      ctx.GetHeader(umtypes.ClientIPHeader),
		UserRole:    ctx.GetHeader(umtypes.UserRoleHeader),
		PartTokenId: utils.UUIDFromString(ctx.GetHeader(umtypes.PartTokenIDHeader)),
	}

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
		UserAgent:   ctx.GetHeader(umtypes.UserAgentHeader),
		FingerPrint: ctx.GetHeader(umtypes.FingerprintHeader),
		UserIp:      ctx.GetHeader(umtypes.ClientIPHeader),
	}

	resp, err := srv.CheckToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Set(umtypes.UserIDHeader, resp.UserId.Value)
	ctx.Set(umtypes.UserRoleHeader, resp.UserRole)
	ctx.Set(umtypes.TokenIDHeader, resp.TokenId.Value)
	ctx.Set(umtypes.PartTokenIDHeader, resp.PartTokenId.Value)

	ctx.JSON(http.StatusOK, gin.H{
		"access": resp.Access,
	})
}

func extendTokenHandler(ctx *gin.Context) {
	req := &auth.ExtendTokenRequest{
		RefreshToken: ctx.Param("refresh_token"),
		Fingerprint:  ctx.GetHeader(umtypes.FingerprintHeader),
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
		UserId: utils.UUIDFromString(ctx.GetHeader(umtypes.UserIDHeader)),
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
		UserId:  utils.UUIDFromString(ctx.GetHeader(umtypes.UserIDHeader)),
	}

	_, err := srv.DeleteToken(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Status(http.StatusOK)
}

func deleteUserTokensHandler(ctx *gin.Context) {
	query := struct {
		UserID string `form:"user_id" binding:"uuid4"`
	}{}

	if err := ctx.ShouldBindQuery(&query); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, errors.New(err.Error()))
		return
	}

	req := &auth.DeleteUserTokensRequest{
		UserId: utils.UUIDFromString(query.UserID),
	}

	_, err := srv.DeleteUserTokens(ctx.Request.Context(), req)
	if err != nil {
		ctx.AbortWithStatusJSON(handleServerError(err))
		return
	}

	ctx.Status(http.StatusOK)
}
