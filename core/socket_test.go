package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedCert generates a self-signed TLS certificate with the given key.
func selfSignedCert(t *testing.T, key interface{}, pub interface{}) tls.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal("create certificate:", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

// tlsPubKeyFromCert creates a TLS server/client pair and returns the client's
// TlsPubKey() result.
func tlsPubKeyFromCert(t *testing.T, cert tls.Certificate) []byte {
	t.Helper()
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	clientConf := &tls.Config{
		InsecureSkipVerify: true,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatal("listen:", err)
	}
	defer ln.Close() //nolint:errcheck

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close() //nolint:errcheck
		tlsConn := conn.(*tls.Conn)
		errCh <- tlsConn.Handshake()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal("dial:", err)
	}
	defer conn.Close() //nolint:errcheck

	sock := NewSocketLayer(conn)
	sock.tlsConn = tls.Client(conn, clientConf)
	if err := sock.tlsConn.Handshake(); err != nil {
		t.Fatal("client handshake:", err)
	}

	if err := <-errCh; err != nil {
		t.Fatal("server handshake:", err)
	}

	pubkey, err := sock.TlsPubKey()
	if err != nil {
		t.Fatal("TlsPubKey:", err)
	}
	return pubkey
}

func TestTlsPubKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSignedCert(t, key, &key.PublicKey)
	got := tlsPubKeyFromCert(t, cert)
	want := x509.MarshalPKCS1PublicKey(&key.PublicKey)

	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("byte %d mismatch: got 0x%02x, want 0x%02x", i, got[i], want[i])
		}
	}
}

func TestTlsPubKey_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSignedCert(t, key, &key.PublicKey)
	got := tlsPubKeyFromCert(t, cert)
	want := elliptic.Marshal(key.Curve, key.X, key.Y)

	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("byte %d mismatch: got 0x%02x, want 0x%02x", i, got[i], want[i])
		}
	}
}

func TestTlsPubKey_Ed25519(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSignedCert(t, key, key.Public())
	got := tlsPubKeyFromCert(t, cert)

	if len(got) != ed25519.PublicKeySize {
		t.Fatalf("length: got %d, want %d", len(got), ed25519.PublicKeySize)
	}
	for i := range got {
		if got[i] != pub[i] {
			t.Fatalf("byte %d mismatch: got 0x%02x, want 0x%02x", i, got[i], pub[i])
		}
	}
}

func TestTlsPubKey_NoTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck

	sock := NewSocketLayer(conn)
	_, err = sock.TlsPubKey()
	if err == nil {
		t.Error("expected error when TLS not established")
	}
}
