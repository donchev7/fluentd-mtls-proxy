package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

type FingerprintValidator interface {
	CheckFingerprint(fingerprint string) bool
}

type Proxy struct {
	listener  net.Listener
	group     *errgroup.Group
	validator FingerprintValidator
	stop      context.CancelFunc
	ctx       context.Context
	cfg       Opts
}

type Opts struct {
	Validator      FingerprintValidator
	ListenAddr     string
	FluentdAddress string
	CertFilePath   string
	KeyFilePath    string
}

func New(in Opts) *Proxy {
	p := Proxy{
		validator: in.Validator,
		group:     &errgroup.Group{},
		cfg:       in,
	}
	p.listener = p.mustListener()

	return &p
}

func (p *Proxy) Start() error {
	log.Printf("Starting Proxy on %s", p.listener.Addr().String())
	p.ctx, p.stop = context.WithCancel(context.Background())

	return p.proxyConnection()
}

func (p *Proxy) mustListener() net.Listener {
	cer, err := tls.LoadX509KeyPair(p.cfg.CertFilePath, p.cfg.KeyFilePath)
	if err != nil {
		log.Panic("Error loading cert/key pair")
	}

	config := &tls.Config{
		Certificates:          []tls.Certificate{cer},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: p.verifyPeer,
		MinVersion:            tls.VersionTLS12,
	}

	l, err := tls.Listen("tcp", p.cfg.ListenAddr, config)
	if err != nil {
		log.Panic("Could not start proxy")
	}

	return l
}

func (p *Proxy) verifyPeer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	fingerprint := sha256.Sum256(cert.Raw)
	digest := hex.EncodeToString(fingerprint[:])

	log.Printf("Got client certificate digest: %s", digest)

	if !p.validator.CheckFingerprint(digest) {
		log.Printf("Client certificate digest %s not allowed", digest)

		return errors.New("unauthorized")
	} else {
		return nil
	}
}

func closeConn(conn *tls.Conn) {
	if err := conn.Close(); err != nil && !isNormalDisconnect(err) {
		if errors.Is(err, syscall.EPIPE) {
			// fluentd closed the connection we (client) opened
			return
		}
		log.Printf("Error closing connection: %s", err)
	}
}

func (p *Proxy) proxyConnection() error {
	for {
		conn, err := p.listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			// listener was closed. Probably because we are shutting down
			return nil
		}

		if err != nil {
			select {
			case <-p.ctx.Done():
				return fmt.Errorf("context cancelled: %w", err)
			default:
				log.Printf("Error accepting connection: %s", err)

				continue
			}
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			log.Println("Error casting connection to tls.Conn")
			closeConn(tlsConn)

			continue
		}

		p.group.Go(func() error {
			defer closeConn(tlsConn)
			err := handleConnection(tlsConn, p.cfg.FluentdAddress)
			if err != nil {
				log.Printf("Error handling connection: %s", err)
			}

			return nil
		})
	}
}

func isNormalDisconnect(err error) bool {
	if err == io.EOF {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}

	return false
}

func handleConnection(conn *tls.Conn, downstreamAddr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) //nolint:gomnd
	defer cancel()

	if err := conn.HandshakeContext(ctx); err != nil {
		if isNormalDisconnect(err) {
			return nil
		}
		return fmt.Errorf("error performing handshake: %w", err)
	}

	fluentdConn, err := net.Dial("tcp", downstreamAddr)
	if err != nil {
		return fmt.Errorf("error connecting to fluentd: %w", err)
	}
	defer fluentdConn.Close()

	written, cerr := io.Copy(fluentdConn, conn)
	log.Printf("Wrote %d bytes to fluentd", written)
	if cerr != nil && !isNormalDisconnect(cerr) {
		return fmt.Errorf("error copying data to fluentd: %w", cerr)
	}

	return nil
}

func (p *Proxy) Close(gracePeriod time.Duration) {
	log.Println("Stopping proxy")
	p.listener.Close()

	connectionErrors := make(chan error)
	go func() {
		connectionErrors <- p.group.Wait()
	}()

	select {
	case err := <-connectionErrors:
		if err == nil {
			log.Println("All connections closed")

			break
		}
		log.Printf("Error waiting for connections to close: %s", err)
	case <-time.After(gracePeriod):
		log.Printf("Timeout waiting for connections to close after %s", gracePeriod)
	}

	p.stop()
	log.Printf("Proxy stopped")
}
