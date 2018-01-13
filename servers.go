package main

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"runtime/debug"

	"context"
	"time"

	"git.containerum.net/ch/auth/routes"
	"git.containerum.net/ch/grpc-proto-files/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	"github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/grpc-opentracing/go/otgrpc"
	"github.com/husobee/vestigo"
	"github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type HTTPServer struct {
	listenAddr string
	server     *http.Server
}

func NewHTTPServer(listenAddr string, tracer opentracing.Tracer, storage auth.AuthServer) *HTTPServer {
	router := vestigo.NewRouter()
	routes.SetupRoutes(router, tracer, storage)
	server := &http.Server{
		Addr:    listenAddr,
		Handler: router,
	}
	return &HTTPServer{
		listenAddr: listenAddr,
		server:     server,
	}
}

func (s *HTTPServer) Run() error {
	logrus.WithField("listenAddr", s.listenAddr).Info("Starting HTTP server")
	return s.server.ListenAndServe()
}

func (s *HTTPServer) Stop() error {
	logrus.Info("Stopping HTTP server")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

type GRPCServer struct {
	listenAddr string
	server     *grpc.Server
}

func panicHandler(p interface{}) (err error) {
	logrus.Errorf("panic: %v", p)
	debug.PrintStack()
	return fmt.Errorf("panic: %v", p)
}

func NewGRPCServer(listenAddr string, tracer opentracing.Tracer, storage auth.AuthServer) *GRPCServer {
	server := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			otgrpc.OpenTracingServerInterceptor(tracer, otgrpc.LogPayloads()),
			grpc_recovery.UnaryServerInterceptor(grpc_recovery.WithRecoveryHandler(panicHandler)),
			grpc_logrus.UnaryServerInterceptor(logrus.WithField("component", "grpc_server")),
		)),
	)
	auth.RegisterAuthServer(server, storage)
	return &GRPCServer{
		listenAddr: listenAddr,
		server:     server,
	}
}

func (s *GRPCServer) Run() error {
	logrus.WithField("listenAddr", s.listenAddr).Infof("Starting GRPC server")
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	return s.server.Serve(listener)
}

func (s *GRPCServer) Stop() error {
	logrus.Infof("Stopping GRPC server")
	s.server.GracefulStop()
	return nil
}

type Server interface {
	Run() error
	Stop() error
}

func RunServers(servers ...Server) {
	for _, server := range servers {
		go func(s Server) {
			if err := s.Run(); err != nil {
				logrus.WithError(err).Error("Run server failed")
				os.Exit(1)
			}
		}(server)
	}
}

func StopServers(servers ...Server) {
	for _, server := range servers {
		if err := server.Stop(); err != nil {
			logrus.WithError(err).Error("Error at stopping server")
		}
	}
}
