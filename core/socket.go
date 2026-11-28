package core

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

type SocketLayer struct {
	conn net.Conn
	// Publish TLS only after construction; Close may race a timed-out handshake.
	tlsConn       atomic.Pointer[tls.Conn]
	ctx           context.Context
	TLSMinVersion uint16
	TLSVerify     bool
}

func NewSocketLayer(conn net.Conn) *SocketLayer {
	l := &SocketLayer{
		conn:          conn,
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
		if tlsConn := s.tlsConn.Load(); tlsConn != nil {
			tlsConn.SetDeadline(deadline)
		}
	}
}

// SetDeadline sets the read and write deadline on the underlying connection.
func (s *SocketLayer) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

func (s *SocketLayer) Read(b []byte) (n int, err error) {
	if tlsConn := s.tlsConn.Load(); tlsConn != nil {
		return tlsConn.Read(b)
	}
	return s.conn.Read(b)
}

func (s *SocketLayer) Write(b []byte) (n int, err error) {
	if tlsConn := s.tlsConn.Load(); tlsConn != nil {
		return tlsConn.Write(b)
	}
	return s.conn.Write(b)
}

func (s *SocketLayer) Close() error {
	if tlsConn := s.tlsConn.Load(); tlsConn != nil {
		err := tlsConn.Close()
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
	tlsConn := tls.Client(s.conn, config)
	s.tlsConn.Store(tlsConn)
	err := tlsConn.Handshake()
	if err != nil {
		return err
	}
	if deadline, ok := s.ctx.Deadline(); ok {
		tlsConn.SetDeadline(deadline)
	}
	return nil
}

func (s *SocketLayer) TlsPubKey() ([]byte, error) {
	tlsConn := s.tlsConn.Load()
	if tlsConn == nil {
		return nil, errors.New("TLS conn does not exist")
	}
	pub, ok := tlsConn.ConnectionState().PeerCertificates[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("server certificate does not contain RSA public key")
	}
	return x509.MarshalPKCS1PublicKey(pub), nil
}
