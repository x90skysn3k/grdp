package tpkt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/emission"
	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/nla"
)

const maxDERFrameSize = 65536

// clientVersion is the highest CredSSP version we advertise.
const clientVersion = 6

// readDERFrame reads a complete DER-encoded TLV from r. It reads the tag and
// length prefix first, then reads exactly the number of value bytes indicated.
func readDERFrame(r io.Reader) ([]byte, error) {
	// Read tag byte
	tag := make([]byte, 1)
	if _, err := io.ReadFull(r, tag); err != nil {
		return nil, fmt.Errorf("read DER tag: %w", err)
	}

	// Read first length byte
	lenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("read DER length: %w", err)
	}

	var totalLen int
	header := []byte{tag[0], lenBuf[0]}

	if lenBuf[0] < 0x80 {
		// Short form: length is the byte itself
		totalLen = int(lenBuf[0])
	} else if lenBuf[0] == 0x80 {
		return nil, fmt.Errorf("indefinite DER length not supported")
	} else {
		// Long form: low 7 bits tell how many bytes encode the length
		numLenBytes := int(lenBuf[0] & 0x7f)
		if numLenBytes > 4 {
			return nil, fmt.Errorf("DER length too large: %d bytes", numLenBytes)
		}
		lenBytes := make([]byte, numLenBytes)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, fmt.Errorf("read DER length bytes: %w", err)
		}
		header = append(header, lenBytes...)
		for _, b := range lenBytes {
			totalLen = (totalLen << 8) | int(b)
		}
	}

	if totalLen > maxDERFrameSize {
		return nil, fmt.Errorf("DER frame too large: %d bytes", totalLen)
	}

	// Read the value
	value := make([]byte, totalLen)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, fmt.Errorf("read DER value: %w", err)
	}

	// Return full TLV
	result := make([]byte, 0, len(header)+totalLen)
	result = append(result, header...)
	result = append(result, value...)
	return result, nil
}

// take idea from https://github.com/Madnikulin50/gordp

/**
 * Type of tpkt packet
 * Fastpath is use to shortcut RDP stack
 * @see http://msdn.microsoft.com/en-us/library/cc240621.aspx
 * @see http://msdn.microsoft.com/en-us/library/cc240589.aspx
 */
const (
	FASTPATH_ACTION_FASTPATH = 0x0
	FASTPATH_ACTION_X224     = 0x3
)

/**
 * TPKT layer of rdp stack
 */
type TPKT struct {
	emission.Emitter
	Conn             *core.SocketLayer
	ntlm             *nla.NTLMv2
	secFlag          byte
	lastShortLength  int
	fastPathListener core.FastPathListener
	ntlmSec          *nla.NTLMv2Security
	ctx              context.Context
	VerifyServer     bool
}

func New(s *core.SocketLayer, ntlm *nla.NTLMv2) *TPKT {
	t := &TPKT{
		Emitter: *emission.NewEmitter(),
		Conn:    s,
		secFlag: 0,
		ntlm:    ntlm,
		ctx:     context.Background(),
	}
	core.StartReadBytes(t.ctx, 2, s, t.recvHeader)
	return t
}

// SetContext updates the TPKT's context for deadline propagation. The existing
// reader goroutine chain continues running and will pick up the new context
// on its next read cycle. The deadline from the context is applied to the
// underlying connection.
func (t *TPKT) SetContext(ctx context.Context) {
	t.ctx = ctx
	t.Conn.SetContext(ctx)
}

func (t *TPKT) StartTLS() error {
	return t.Conn.StartTLS()
}

// generateNonce creates a 32-byte cryptographically random nonce for CredSSP v5+.
func generateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}

// computeHash computes SHA256(magic || nonce || pubkey) as required by CredSSP v5+.
func computeHash(magic string, nonce, pubkey []byte) []byte {
	h := sha256.New()
	h.Write([]byte(magic))
	h.Write(nonce)
	h.Write(pubkey)
	return h.Sum(nil)
}

// checkErrorCode returns a descriptive error if the TSRequest contains a
// non-zero ErrorCode.
func checkErrorCode(tsreq *nla.TSRequest) error {
	if tsreq.ErrorCode == 0 {
		return nil
	}
	code := uint32(tsreq.ErrorCode)
	desc := fmt.Sprintf("NTSTATUS 0x%08X", code)
	switch code {
	case 0xC0000022:
		desc += " (STATUS_ACCESS_DENIED)"
	case 0xC000006D:
		desc += " (STATUS_LOGON_FAILURE)"
	case 0xC000006E:
		desc += " (STATUS_ACCOUNT_RESTRICTION)"
	case 0x80090346:
		desc += " (SEC_E_DELEGATION_POLICY)"
	}
	return fmt.Errorf("CredSSP server error: %s", desc)
}

func (t *TPKT) StartNLA() error {
	if err := t.ctx.Err(); err != nil {
		return err
	}
	err := t.StartTLS()
	if err != nil {
		glog.Info("start tls failed", err)
		return err
	}

	// Generate nonce for v5+ pubkey hash computation. We generate it up front
	// and reuse the same nonce for the entire exchange.
	nonce, err := generateNonce()
	if err != nil {
		return err
	}

	// Send NegotiateMessage advertising our highest CredSSP version.
	// The nonce is NOT included in the first message (only in step 3).
	req := nla.EncodeDERTRequest(clientVersion,
		[]nla.Message{t.ntlm.GetNegotiateMessage()}, nil, nil, nil)
	if err := t.ctx.Err(); err != nil {
		return err
	}
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send NegotiateMessage", err)
		return err
	}

	if err := t.ctx.Err(); err != nil {
		return err
	}
	resp, err := readDERFrame(t.Conn)
	if err != nil {
		return fmt.Errorf("read NLA challenge: %w", err)
	}
	glog.Debug("StartNLA Read success")
	return t.recvChallenge(resp, nonce)
}

func (t *TPKT) recvChallenge(data []byte, nonce []byte) error {
	if err := t.ctx.Err(); err != nil {
		return err
	}
	glog.Trace("recvChallenge", hex.EncodeToString(data))
	tsreq, err := nla.DecodeDERTRequest(data)
	if err != nil {
		glog.Info("DecodeDERTRequest", err)
		return err
	}
	glog.Debugf("tsreq:%+v", tsreq)

	if err := checkErrorCode(tsreq); err != nil {
		return err
	}

	// get pubkey
	pubkey, err := t.Conn.TlsPubKey()
	if err != nil {
		return fmt.Errorf("get TLS public key: %w", err)
	}
	glog.Debugf("pubkey=%+v", pubkey)

	if len(tsreq.NegoTokens) == 0 {
		return fmt.Errorf("no NegoTokens in response (server version %d)", tsreq.Version)
	}

	// Negotiate effective CredSSP version: min(ours, server's)
	effectiveVersion := tsreq.Version
	if clientVersion < effectiveVersion {
		effectiveVersion = clientVersion
	}
	glog.Debugf("CredSSP version negotiation: client=%d server=%d effective=%d",
		clientVersion, tsreq.Version, effectiveVersion)

	authMsg, ntlmSec := t.ntlm.GetAuthenticateMessage(tsreq.NegoTokens[0].Data)
	t.ntlmSec = ntlmSec

	var reqBytes []byte
	if effectiveVersion >= 5 {
		// v5+: send SHA-256 hash of (magic || nonce || pubkey) instead of raw pubkey
		hash := computeHash("CredSSP Client-To-Server Binding Hash\x00", nonce, pubkey)
		encryptedHash := ntlmSec.GssEncrypt(hash)
		reqBytes = nla.EncodeDERTRequest(clientVersion,
			[]nla.Message{authMsg}, nil, encryptedHash, nonce)
	} else {
		// v2-v4: send encrypted raw public key
		encryptPubkey := ntlmSec.GssEncrypt(pubkey)
		reqBytes = nla.EncodeDERTRequest(clientVersion,
			[]nla.Message{authMsg}, nil, encryptPubkey, nil)
	}

	if err := t.ctx.Err(); err != nil {
		return err
	}
	_, err = t.Conn.Write(reqBytes)
	if err != nil {
		glog.Info("send AuthenticateMessage", err)
		return err
	}
	if err := t.ctx.Err(); err != nil {
		return err
	}
	resp, err := readDERFrame(t.Conn)
	if err != nil {
		glog.Error("Read:", err)
		return fmt.Errorf("read NLA pubkey response: %w", err)
	}
	glog.Debug("recvChallenge Read success")
	return t.recvPubKeyInc(resp, effectiveVersion, nonce, pubkey)
}

func (t *TPKT) recvPubKeyInc(data []byte, effectiveVersion int, nonce, pubkey []byte) error {
	if err := t.ctx.Err(); err != nil {
		return err
	}
	glog.Trace("recvPubKeyInc", hex.EncodeToString(data))
	tsreq, err := nla.DecodeDERTRequest(data)
	if err != nil {
		glog.Info("DecodeDERTRequest", err)
		return err
	}

	if err := checkErrorCode(tsreq); err != nil {
		return err
	}

	glog.Trace("PubKeyAuth:", tsreq.PubKeyAuth)

	if t.VerifyServer && len(tsreq.PubKeyAuth) > 0 {
		serverPubKey := t.ntlmSec.GssDecrypt([]byte(tsreq.PubKeyAuth))

		if effectiveVersion >= 5 {
			// v5+: verify SHA-256 hash
			expected := computeHash("CredSSP Server-To-Client Binding Hash\x00", nonce, pubkey)
			if len(serverPubKey) != len(expected) {
				return fmt.Errorf("server PubKeyAuth verification failed: length mismatch")
			}
			match := true
			for i := range serverPubKey {
				if serverPubKey[i] != expected[i] {
					match = false
					break
				}
			}
			if !match {
				return fmt.Errorf("server PubKeyAuth verification failed: possible MITM")
			}
		} else {
			// v2-v4: server returns pubkey with first byte incremented by 1
			expected := make([]byte, len(pubkey))
			copy(expected, pubkey)
			if len(expected) > 0 {
				expected[0]++
			}
			if len(serverPubKey) != len(expected) {
				return fmt.Errorf("server PubKeyAuth verification failed: length mismatch")
			}
			match := true
			for i := range serverPubKey {
				if serverPubKey[i] != expected[i] {
					match = false
					break
				}
			}
			if !match {
				return fmt.Errorf("server PubKeyAuth verification failed: possible MITM")
			}
		}
		glog.Debug("Server PubKeyAuth verified successfully")
	}

	domain, username, password := t.ntlm.GetEncodedCredentials()
	credentials := nla.EncodeDERTCredentials(domain, username, password)
	authInfo := t.ntlmSec.GssEncrypt(credentials)
	req := nla.EncodeDERTRequest(clientVersion, nil, authInfo, nil, nil)
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send AuthenticateMessage", err)
		return err
	}

	return nil
}

func (t *TPKT) Read(b []byte) (n int, err error) {
	return t.Conn.Read(b)
}

func (t *TPKT) Write(data []byte) (n int, err error) {
	buff := &bytes.Buffer{}
	core.WriteUInt8(FASTPATH_ACTION_X224, buff)
	core.WriteUInt8(0, buff)
	core.WriteUInt16BE(uint16(len(data)+4), buff)
	buff.Write(data)
	glog.Trace("tpkt Write", hex.EncodeToString(buff.Bytes()))
	return t.Conn.Write(buff.Bytes())
}

func (t *TPKT) Close() error {
	t.Emitter.Close()
	return t.Conn.Close()
}

func (t *TPKT) SetFastPathListener(f core.FastPathListener) {
	t.fastPathListener = f
}

func (t *TPKT) SendFastPath(secFlag byte, data []byte) (n int, err error) {
	buff := &bytes.Buffer{}
	core.WriteUInt8(FASTPATH_ACTION_FASTPATH|((secFlag&0x3)<<6), buff)
	core.WriteUInt16BE(uint16(len(data)+3)|0x8000, buff)
	buff.Write(data)
	glog.Trace("TPTK SendFastPath", hex.EncodeToString(buff.Bytes()))
	return t.Conn.Write(buff.Bytes())
}

func (t *TPKT) recvHeader(s []byte, err error) {
	glog.Trace("tpkt recvHeader", hex.EncodeToString(s), err)
	if err != nil {
		t.Emit("error", err)
		return
	}
	r := bytes.NewReader(s)
	version, _ := core.ReadUInt8(r)
	if version == FASTPATH_ACTION_X224 {
		glog.Debug("tptk recvHeader FASTPATH_ACTION_X224, wait for recvExtendedHeader")
		core.StartReadBytes(t.ctx, 2, t.Conn, t.recvExtendedHeader)
	} else {
		t.secFlag = (version >> 6) & 0x3
		length, _ := core.ReadUInt8(r)
		t.lastShortLength = int(length)
		if t.lastShortLength&0x80 != 0 {
			core.StartReadBytes(t.ctx, 1, t.Conn, t.recvExtendedFastPathHeader)
		} else {
			core.StartReadBytes(t.ctx, t.lastShortLength-2, t.Conn, t.recvFastPath)
		}
	}
}

func (t *TPKT) recvExtendedHeader(s []byte, err error) {
	glog.Trace("tpkt recvExtendedHeader", hex.EncodeToString(s), err)
	if err != nil {
		return
	}
	r := bytes.NewReader(s)
	size, _ := core.ReadUint16BE(r)
	glog.Debug("tpkt wait recvData:", size)
	core.StartReadBytes(t.ctx, int(size-4), t.Conn, t.recvData)
}

func (t *TPKT) recvData(s []byte, err error) {
	glog.Trace("tpkt recvData", hex.EncodeToString(s), err)
	if err != nil {
		return
	}
	t.Emit("data", s)
	core.StartReadBytes(t.ctx, 2, t.Conn, t.recvHeader)
}

func (t *TPKT) recvExtendedFastPathHeader(s []byte, err error) {
	glog.Trace("tpkt recvExtendedFastPathHeader", hex.EncodeToString(s))
	r := bytes.NewReader(s)
	rightPart, err := core.ReadUInt8(r)
	if err != nil {
		glog.Error("TPTK recvExtendedFastPathHeader", err)
		return
	}

	leftPart := t.lastShortLength & ^0x80
	packetSize := (leftPart << 8) + int(rightPart)
	core.StartReadBytes(t.ctx, packetSize-3, t.Conn, t.recvFastPath)
}

func (t *TPKT) recvFastPath(s []byte, err error) {
	glog.Trace("tpkt recvFastPath")
	if err != nil {
		return
	}

	t.fastPathListener.RecvFastPath(t.secFlag, s)
	core.StartReadBytes(t.ctx, 2, t.Conn, t.recvHeader)
}
