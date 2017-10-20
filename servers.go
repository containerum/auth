package main

import (
	"net"
	"net/http"
	"os"
	"sync"

	"bitbucket.org/exonch/ch-auth/routes"
	"bitbucket.org/exonch/ch-grpc/auth"
	"github.com/grpc-ecosystem/grpc-opentracing/go/otgrpc"
	"github.com/husobee/vestigo"
	"github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type HTTPServer struct {
	listenAddr string
	router     *vestigo.Router
}

func NewHTTPServer(listenAddr string, tracer opentracing.Tracer, storage auth.AuthServer) *HTTPServer {
	router := vestigo.NewRouter()
	routes.SetupRoutes(router, tracer, storage)
	return &HTTPServer{
		listenAddr: listenAddr,
		router:     router,
	}
}

func (s *HTTPServer) Run() error {
	logrus.WithField("listenAddr", s.listenAddr).Info("Starting HTTP server")
	return http.ListenAndServe(s.listenAddr, s.router)
}

type GRPCServer struct {
	listenAddr string
	server     *grpc.Server
}

func NewGRPCServer(listenAddr string, tracer opentracing.Tracer, storage auth.AuthServer) *GRPCServer {
	server := grpc.NewServer(grpc.UnaryInterceptor(otgrpc.OpenTracingServerInterceptor(tracer, otgrpc.LogPayloads())))
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

type Runnable interface {
	Run() error
}

func RunServers(servers ...Runnable) {
	wg := &sync.WaitGroup{}
	wg.Add(len(servers))
	for _, server := range servers {
		go func() {
			if err := server.Run(); err != nil {
				logrus.Errorf("run server: %v", err)
				os.Exit(1)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
