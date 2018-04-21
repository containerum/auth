package main

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"strings"

	"fmt"

	"git.containerum.net/ch/auth/pkg/storages"
	"git.containerum.net/ch/auth/pkg/token"
	"git.containerum.net/ch/auth/proto"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/locales/en"
	"github.com/go-playground/locales/en_US"
	"github.com/go-playground/universal-translator"
	"github.com/opentracing/opentracing-go"
	"github.com/openzipkin/zipkin-go-opentracing"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/buntdb"
	"gopkg.in/urfave/cli.v2"
)

func appendError(errs []string, err error) []string {
	if err != nil {
		return append(errs, err.Error())
	}
	return errs
}

func setError(errs []string) error {
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, ";"))
}

func getJWTConfig(ctx *cli.Context) (cfg token.JWTIssuerValidatorConfig, err error) {
	var errs []string

	cfg.SigningMethod = jwt.GetSigningMethod(ctx.String(JWTSigningMethodFlag.Name))
	if cfg.SigningMethod == nil {
		errs = append(errs, "signing method not found")
	}

	cfg.Issuer = ctx.String(IssuerFlag.Name)

	cfg.AccessTokenLifeTime = ctx.Duration(AccessTokenLifeTimeFlag.Name)
	if cfg.AccessTokenLifeTime <= 0 {
		errs = append(errs, "access token lifetime is invalid or not set")
	}

	cfg.RefreshTokenLifeTime = ctx.Duration(RefreshTokenLifeTimeFlag.Name)
	if cfg.RefreshTokenLifeTime <= cfg.AccessTokenLifeTime {
		errs = append(errs, "refresh token lifetime must be greater than access token lifetime")
	}

	signingKeyFile := ctx.String(JWTSigningKeyFileFlag.Name)
	validationKeyFile := ctx.String(JWTValidationKeyFileFlag.Name)

	signingKeyFileCont, err := ioutil.ReadFile(signingKeyFile)
	if err != nil {
		errs = appendError(errs, fmt.Errorf("signing key read failed: %v", err))
	}

	validationKeyFileCont, err := ioutil.ReadFile(validationKeyFile)
	if err != nil {
		errs = appendError(errs, fmt.Errorf("validation key read failed: %v", err))
	}

	switch cfg.SigningMethod.(type) {
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		cfg.SigningKey, err = jwt.ParseRSAPrivateKeyFromPEM(signingKeyFileCont)
		errs = appendError(errs, err)
		cfg.ValidationKey, err = jwt.ParseRSAPublicKeyFromPEM(validationKeyFileCont)
		errs = appendError(errs, err)
	case *jwt.SigningMethodECDSA:
		cfg.SigningKey, err = jwt.ParseECPrivateKeyFromPEM(signingKeyFileCont)
		errs = appendError(errs, err)
		cfg.ValidationKey, err = jwt.ParseECPublicKeyFromPEM(validationKeyFileCont)
		errs = appendError(errs, err)
	default:
		signingKeyBuf := make([]byte, base64.StdEncoding.DecodedLen(len(signingKeyFileCont)))
		validationKeyBuf := make([]byte, base64.StdEncoding.DecodedLen(len(validationKeyFileCont)))
		_, err := base64.StdEncoding.Decode(signingKeyBuf, signingKeyFileCont)
		errs = appendError(errs, err)
		cfg.SigningKey = signingKeyBuf
		_, err = base64.StdEncoding.Decode(validationKeyBuf, validationKeyFileCont)
		errs = appendError(errs, err)
		cfg.ValidationKey = validationKeyBuf
	}

	return cfg, setError(errs)
}

func getTokenIssuerValidator(ctx *cli.Context) (iv token.IssuerValidator, err error) {
	tokens := ctx.String(TokensFlag.Name)
	switch tokens {
	case "jwt":
		cfg, err := getJWTConfig(ctx)
		if err != nil {
			return nil, err
		}
		iv = token.NewJWTIssuerValidator(cfg)
		return iv, nil
	default:
		return nil, errors.New("invalid token issuer-validator")
	}
}

func getBuntDBStorageConfig(ctx *cli.Context, tokenFactory token.IssuerValidator) (cfg storages.BuntDBStorageConfig, err error) {
	var errs []string
	cfg.File = ctx.String(BuntStorageFileFlag.Name)

	cfg.BuntDBConfig.SyncPolicy = buntdb.SyncPolicy(ctx.Int(BuntSyncPolicyFlag.Name))
	switch cfg.BuntDBConfig.SyncPolicy {
	case buntdb.EverySecond, buntdb.Never, buntdb.Always:
	default:
		errs = append(errs, "invalid bunt_syncpolicy")
	}

	cfg.BuntDBConfig.AutoShrinkDisabled = ctx.Bool(BuntAutoShrinkDisabledFlag.Name)

	if ctx.IsSet(BuntAutoShrinkMinSizeFlag.Name) {
		cfg.BuntDBConfig.AutoShrinkMinSize = ctx.Int(BuntAutoShrinkMinSizeFlag.Name)
	}

	if ctx.IsSet(BuntAutoShrinkPercentageFlag.Name) {
		cfg.BuntDBConfig.AutoShrinkPercentage = ctx.Int(BuntAutoShrinkPercentageFlag.Name)
	}

	cfg.TokenFactory = tokenFactory

	return cfg, setError(errs)
}

func getStorage(ctx *cli.Context) (storage authProto.AuthServer, err error) {
	tokenFactory, err := getTokenIssuerValidator(ctx)
	if err != nil {
		return nil, err
	}

	switch ctx.String(StorageFlag.Name) {
	case "buntdb":
		var cfg storages.BuntDBStorageConfig
		cfg, err = getBuntDBStorageConfig(ctx, tokenFactory)
		if err != nil {
			return nil, err
		}
		storage, err = storages.NewBuntDBStorage(cfg)
		return
	default:
		return nil, errors.New("invalid storage")
	}
}

func getZipkinCollector(ctx *cli.Context) (collector zipkintracer.Collector, err error) {
	switch ctx.String(ZipkinCollectorFlag.Name) {
	case "http":
		collector, err = zipkintracer.NewHTTPCollector(ctx.String(ZipkinHTTPCollectorURLFlag.Name))
	case "kafka":
		collector, err = zipkintracer.NewKafkaCollector(ctx.StringSlice(ZipkinKafkaCollectorAddrsFlag.Name))
	case "scribe":
		collector, err = zipkintracer.NewScribeCollector(ctx.String(ZipkinScribeCollectorAddrFlag.Name),
			ctx.Duration(ZipkinScribeCollectorDurationFlag.Name))
	case "nop":
		collector = zipkintracer.NopCollector{}
	default:
		err = errors.New("invalid zipkin collector")
	}
	return
}

func getTracer(ctx *cli.Context, hostPort, service string) (tracer opentracing.Tracer, err error) {
	switch ctx.String(TracerFlag.Name) {
	case "zipkin":
		collector, collErr := getZipkinCollector(ctx)
		if collErr != nil {
			return nil, collErr
		}
		tracer, err = zipkintracer.NewTracer(zipkintracer.NewRecorder(collector,
			ctx.Bool(ZipkinRecorderDebugFlag.Name), hostPort, service))
	default:
		err = errors.New("invalid opentracing tracer found")
	}
	return
}

func logModeSetup(ctx *cli.Context) error {
	switch ctx.String(LogModeFlag.Name) {
	case "text":
		logrus.SetFormatter(&logrus.TextFormatter{})
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{})
	default:
		return errors.New("invalid log mode")
	}
	return nil
}

func logLevelSetup(ctx *cli.Context) error {
	level := logrus.Level(ctx.Int(LogLevelFlag.Name))
	if level > logrus.DebugLevel || level < logrus.PanicLevel {
		return errors.New("invalid log level")
	}
	logrus.SetLevel(level)
	return nil
}

func setupTranslator() *ut.UniversalTranslator {
	return ut.New(en.New(), en.New(), en_US.New())
}
