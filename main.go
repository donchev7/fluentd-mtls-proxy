package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/donchev7/fluentd-mtls-proxy/proxy"

	"golang.org/x/sync/errgroup"
)

type nOpValidator struct{}

func (nOpValidator) CheckFingerprint(fingerprint string) bool {
	return true
}

func main() {
	gracePeriod := 30 * time.Second
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	p := proxy.New(proxy.Opts{
		ListenAddr:     "localhost:8080",
		FluentdAddress: "localhost:24224",
		CertFilePath:   "test-cert.pem",
		KeyFilePath:    "test-key.pem",
		Validator:      nOpValidator{},
	})

	g, gCtx := errgroup.WithContext(context.Background())

	g.Go(p.Start)

	select {
	case <-ctx.Done():
		log.Println("Received interrupt signal, shutting down")
	case <-gCtx.Done():
		log.Printf("Proxy failed: %v", gCtx.Err())
	}

	p.Close(gracePeriod)
}
