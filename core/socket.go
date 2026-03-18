package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

type SocketLayer struct {
	conn          net.Conn
	tlsConn       *tls.Conn
	ctx           context.Context
	TLSMinVersion uint16
	TLSVerify     bool
}

func NewSocketLayer(conn net.Conn) *SocketLayer {
	l := &SocketLayer{
		conn:          conn,
		tlsConn:       nil,
		ctx:           context.Background(),
		TLSMinVersion: tls.VersionTLS12,
	}
	return l
}

// SetContext sets a context for deadline propagation. If the context has a
// deadline, it is applied to the underlying connection immediately.
func (s *SocketLayer) SetContext(ctx context.Context) {
	s.ctx = ctx
	if deadline, ok := ctx.Deadline(); ok {
		s.conn.SetDeadline(deadline)
		if s.tlsConn != nil {
			s.tlsConn.SetDeadline(deadline)
		}
	}
}

// SetDeadline sets the read and write deadline on the underlying connection.
func (s *SocketLayer) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

func (s *SocketLayer) Read(b []byte) (n int, err error) {
	if s.tlsConn != nil {
		return s.tlsConn.Read(b)
	}
	return s.conn.Read(b)
}

func (s *SocketLayer) Write(b []byte) (n int, err error) {
	if s.tlsConn != nil {
		return s.tlsConn.Write(b)
	}
	return s.conn.Write(b)
}

func (s *SocketLayer) Close() error {
	if s.tlsConn != nil {
		err := s.tlsConn.Close()
		if err != nil {
			return err
		}
	}
	return s.conn.Close()
}

func (s *SocketLayer) StartTLS() error {
	minVer := s.TLSMinVersion
	if minVer == 0 {
		minVer = tls.VersionTLS12
	}
	config := &tls.Config{
		InsecureSkipVerify: !s.TLSVerify,
		MinVersion:         minVer,
		MaxVersion:         tls.VersionTLS13,
	}
	s.tlsConn = tls.Client(s.conn, config)
	err := s.tlsConn.Handshake()
	if err != nil {
		return err
	}
	if deadline, ok := s.ctx.Deadline(); ok {
		s.tlsConn.SetDeadline(deadline)
	}
	return nil
}

// TlsPubKey extracts the server's public key in its type-specific DER encoding.
// For RSA this is PKCS#1, for ECDSA the uncompressed EC point, for Ed25519 the
// raw 32-byte key. This matches what Microsoft SChannel and FreeRDP use for the
// CredSSP public key hash computation.
func (s *SocketLayer) TlsPubKey() ([]byte, error) {
	if s.tlsConn == nil {
		return nil, errors.New("TLS conn does not exist")
	}
	certs := s.tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no peer certificates")
	}
	switch pub := certs[0].PublicKey.(type) {
	case *rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(pub), nil
	case *ecdsa.PublicKey:
		return elliptic.Marshal(pub.Curve, pub.X, pub.Y), nil
	case ed25519.PublicKey:
		return []byte(pub), nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}
