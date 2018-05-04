package main

import (
	"time"

	"github.com/sirupsen/logrus"
	"github.com/tidwall/buntdb"
	"gopkg.in/urfave/cli.v2"
)

// App options
var (
	/*
		LOGGING
	*/

	LogLevelFlag = cli.IntFlag{
		Name:    "log_level",
		EnvVars: []string{"CH_AUTH_LOG_LEVEL"},
		Value:   int(logrus.InfoLevel),
	}

	LogModeFlag = cli.StringFlag{
		Name:    "log_mode",
		EnvVars: []string{"CH_AUTH_LOG_MODE"},
		Value:   "text",
	}

	/*
		TOKENS FACTORY
	*/

	TokensFlag = cli.StringFlag{
		Name:    "tokens",
		EnvVars: []string{"CH_AUTH_TOKENS"},
		Value:   "jwt",
	}

	JWTSigningMethodFlag = cli.StringFlag{
		Name:    "jwt_signing_method",
		EnvVars: []string{"CH_AUTH_JWT_SIGNING_METHOD"},
		Value:   "HS256",
	}

	IssuerFlag = cli.StringFlag{
		Name:    "issuer",
		EnvVars: []string{"CH_AUTH_ISSUER"},
		Value:   "my-company-name",
	}

	AccessTokenLifeTimeFlag = cli.DurationFlag{
		Name:    "access_token_lifetime",
		EnvVars: []string{"CH_AUTH_ACCESS_TOKEN_LIFETIME"},
		Value:   15 * time.Minute,
	}

	RefreshTokenLifeTimeFlag = cli.DurationFlag{
		Name:    "refresh_token_lifetime",
		EnvVars: []string{"CH_AUTH_REFRESH_TOKEN_LIFETIME"},
		Value:   48 * time.Hour,
	}

	JWTSigningKeyFileFlag = cli.StringFlag{
		Name:    "jwt_signing_key_file",
		EnvVars: []string{"CH_AUTH_JWT_SIGNING_KEY_FILE"},
	}

	JWTValidationKeyFileFlag = cli.StringFlag{
		Name:    "jwt_validation_key_file",
		EnvVars: []string{"CH_AUTH_JWT_VALIDATION_KEY_FILE"},
	}

	/*
		TOKENS STORAGE
	*/

	StorageFlag = cli.StringFlag{
		Name:    "storage",
		EnvVars: []string{"CH_AUTH_STORAGE"},
		Value:   "buntdb",
	}

	BuntStorageFileFlag = cli.StringFlag{
		Name:    "bunt_storage_file",
		EnvVars: []string{"CH_AUTH_BUNT_STORAGE_FILE"},
		Value:   "storage.db",
	}

	BuntSyncPolicyFlag = cli.IntFlag{
		Name:    "bunt_syncpolicy",
		EnvVars: []string{"CH_AUTH_BUNT_SYNCPOLICY"},
		Value:   int(buntdb.EverySecond),
	}

	BuntAutoShrinkDisabledFlag = cli.BoolFlag{
		Name:    "bunt_autoshrink_disabled",
		EnvVars: []string{"CH_AUTH_BUNT_AUTOSHRINK_DISABLED"},
		Value:   false,
	}

	BuntAutoShrinkMinSizeFlag = cli.IntFlag{
		Name:    "bunt_autoshrink_minsize",
		EnvVars: []string{"CH_AUTH_BUNT_AUTOSHRINK_MINSIZE"},
	}

	BuntAutoShrinkPercentageFlag = cli.IntFlag{
		Name:    "bunt_autoshrink_percentage",
		EnvVars: []string{"CH_AUTH_BUNT_AUTOSHRINK_PERCENTAGE"},
	}

	/*
		OPENTRACING
	*/

	TracerFlag = cli.StringFlag{
		Name:    "tracer",
		EnvVars: []string{"CH_AUTH_TRACER"},
		Value:   "zipkin",
	}

	ZipkinCollectorFlag = cli.StringFlag{
		Name:    "zipkin_collector",
		EnvVars: []string{"CH_AUTH_ZIPKIN_COLLECTOR"},
		Value:   "nop",
	}

	ZipkinHTTPCollectorURLFlag = cli.StringFlag{
		Name:    "zipkin_http_collector_url",
		EnvVars: []string{"CH_AUTH_ZIPKIN_HTTP_COLLECTOR_URL"},
	}

	ZipkinKafkaCollectorAddrsFlag = cli.StringSliceFlag{
		Name:    "zipkin_kafka_collector_addrs",
		EnvVars: []string{"CH_AUTH_ZIPKIN_KAFKA_COLLECTOR_ADDRS"},
	}

	ZipkinScribeCollectorAddrFlag = cli.StringFlag{
		Name:    "zipkin_scribe_collector_addr",
		EnvVars: []string{"CH_AUTH_ZIPKIN_SCRIBE_COLLECTOR_ADDR"},
	}

	ZipkinScribeCollectorDurationFlag = cli.DurationFlag{
		Name:    "zipkin_scribe_collector_duration",
		EnvVars: []string{"CH_AUTH_ZIPKIN_SCRIBE_COLLECTOR_DURATION"},
	}

	ZipkinRecorderDebugFlag = cli.BoolFlag{
		Name:    "zipkin_recorder_debug",
		EnvVars: []string{"CH_AUTH_ZIPKIN_RECORDER_DEBUG"},
		Value:   false,
	}

	/*
		LISTENING
	*/

	HTTPListenAddrFlag = cli.StringFlag{
		Name:    "http_listenaddr",
		EnvVars: []string{"CH_AUTH_HTTP_LISTENADDR"},
		Value:   ":8080",
	}

	GRPCListenAddrFlag = cli.StringFlag{
		Name:    "grpc_listenaddr",
		EnvVars: []string{"CH_AUTH_GRPC_LISTENADDR"},
		Value:   ":8888",
	}

	/*
		OTHER
	*/

	CORSFlag = cli.BoolFlag{
		Name: "cors",
	}
)
