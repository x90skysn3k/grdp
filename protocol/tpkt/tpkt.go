package tpkt

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/emission"
	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/nla"
)

const maxDERFrameSize = 65536

// readDERFrame reads a complete DER-encoded TLV from r. It reads the tag and
// length prefix first, then reads exactly the number of value bytes indicated.
func readDERFrame(r io.Reader) ([]byte, error) {
	// Read tag byte
	tag := make([]byte, 1)
	if _, err := io.ReadFull(r, tag); err != nil {
		return nil, fmt.Errorf("read DER tag: %w", err)
	}
	if tag[0] != 0x30 {
		return nil, nlaFailure(core.ErrKindProtocol, "invalid CredSSP DER sequence tag", nil)
	}

	// Read first length byte
	lenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("read DER length: %w", err)
	}

	var totalLen uint64
	header := []byte{tag[0], lenBuf[0]}

	if lenBuf[0] < 0x80 {
		// Short form: length is the byte itself
		totalLen = uint64(lenBuf[0])
	} else if lenBuf[0] == 0x80 {
		return nil, nlaFailure(core.ErrKindProtocol, "indefinite CredSSP DER length", nil)
	} else {
		// Long form: low 7 bits tell how many bytes encode the length
		numLenBytes := int(lenBuf[0] & 0x7f)
		if numLenBytes > 4 {
			return nil, nlaFailure(core.ErrKindProtocol, "CredSSP DER length too large", nil)
		}
		lenBytes := make([]byte, numLenBytes)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, fmt.Errorf("read DER length bytes: %w", err)
		}
		header = append(header, lenBytes...)
		for _, b := range lenBytes {
			totalLen = (totalLen << 8) | uint64(b)
		}
	}

	if totalLen > maxDERFrameSize {
		return nil, nlaFailure(core.ErrKindProtocol, "CredSSP DER frame too large", nil)
	}

	// Read the value
	value := make([]byte, int(totalLen))
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, fmt.Errorf("read DER value: %w", err)
	}

	// Return full TLV
	result := make([]byte, 0, len(header)+int(totalLen))
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

// Preserve typed failures across NLA/X224. Only an explicit credential-rejection
// status is authentication failure; malformed messages and I/O are not.
func nlaFailure(kind core.RDPErrorKind, message string, err error) error {
	var rdpErr *core.RDPError
	if errors.As(err, &rdpErr) {
		return err
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		(errors.As(err, &netErr) && netErr.Timeout()) {
		kind = core.ErrKindTimeout
	}
	return &core.RDPError{Kind: kind, Message: message, Wrapped: err}
}

func credSSPStatus(code int64) error {
	if code == 0 {
		return nil
	}
	kind := core.ErrKindProtocol
	switch code {
	case 0xc0000064, // STATUS_NO_SUCH_USER
		0xc000006a, // STATUS_WRONG_PASSWORD
		0xc000006d, // STATUS_LOGON_FAILURE
		0xc000006e, // STATUS_ACCOUNT_RESTRICTION
		0xc000006f, // STATUS_INVALID_LOGON_HOURS
		0xc0000070, // STATUS_INVALID_WORKSTATION
		0xc0000071, // STATUS_PASSWORD_EXPIRED
		0xc0000072, // STATUS_ACCOUNT_DISABLED
		0xc000015b, // STATUS_LOGON_TYPE_NOT_GRANTED
		0xc0000193, // STATUS_ACCOUNT_EXPIRED
		0xc0000224, // STATUS_PASSWORD_MUST_CHANGE
		0xc0000234: // STATUS_ACCOUNT_LOCKED_OUT
		kind = core.ErrKindAuth
	}
	return nlaFailure(kind, fmt.Sprintf("CredSSP server returned NTSTATUS 0x%08x", code), nil)
}

func (t *TPKT) StartNLA() error {
	if err := t.ctx.Err(); err != nil {
		return nlaFailure(core.ErrKindTimeout, "NLA context ended", err)
	}
	err := t.StartTLS()
	if err != nil {
		glog.Info("start tls failed", err)
		return nlaFailure(core.ErrKindTLS, "NLA TLS handshake failed", err)
	}
	req := nla.EncodeDERTRequest([]nla.Message{t.ntlm.GetNegotiateMessage()}, nil, nil)
	if err := t.ctx.Err(); err != nil {
		return nlaFailure(core.ErrKindTimeout, "NLA context ended", err)
	}
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send NegotiateMessage", err)
		return nlaFailure(core.ErrKindNetwork, "send NLA negotiate message", err)
	}

	if err := t.ctx.Err(); err != nil {
		return nlaFailure(core.ErrKindTimeout, "NLA context ended", err)
	}
	resp, err := readDERFrame(t.Conn)
	if err != nil {
		return nlaFailure(core.ErrKindNetwork, "read NLA challenge", err)
	}
	glog.Debug("StartNLA Read success")
	return t.recvChallenge(resp)
}

func (t *TPKT) recvChallenge(data []byte) error {
	if err := t.ctx.Err(); err != nil {
		return nlaFailure(core.ErrKindTimeout, "NLA context ended", err)
	}
	glog.Trace("recvChallenge", hex.EncodeToString(data))
	tsreq, err := nla.DecodeDERTRequest(data)
	if err != nil {
		glog.Info("DecodeDERTRequest", err)
		return nlaFailure(core.ErrKindProtocol, "decode NLA challenge", err)
	}
	glog.Debugf("tsreq:%+v", tsreq)
	if err := credSSPStatus(tsreq.ErrorCode); err != nil {
		return err
	}
	if len(tsreq.NegoTokens) != 1 {
		return nlaFailure(core.ErrKindProtocol, "expected one NTLM challenge token", nil)
	}
	authMsg, ntlmSec := t.ntlm.GetAuthenticateMessage(tsreq.NegoTokens[0].Data)
	if authMsg == nil || ntlmSec == nil {
		return nlaFailure(core.ErrKindProtocol, "invalid NTLM challenge", nil)
	}
	pubkey, err := t.Conn.TlsPubKey()
	if err != nil {
		return nlaFailure(core.ErrKindTLS, "read TLS server public key", err)
	}
	t.ntlmSec = ntlmSec
	encryptPubkey := ntlmSec.GssEncrypt(pubkey)
	req := nla.EncodeDERTRequest([]nla.Message{authMsg}, nil, encryptPubkey)
	if err := t.ctx.Err(); err != nil {
		return nlaFailure(core.ErrKindTimeout, "NLA context ended", err)
	}
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send AuthenticateMessage", err)
		return nlaFailure(core.ErrKindNetwork, "send NLA authenticate message", err)
	}
	if err := t.ctx.Err(); err != nil {
		return nlaFailure(core.ErrKindTimeout, "NLA context ended", err)
	}
	resp, err := readDERFrame(t.Conn)
	if err != nil {
		glog.Error("Read:", err)
		return nlaFailure(core.ErrKindNetwork, "read NLA pubkey response", err)
	}
	glog.Debug("recvChallenge Read success")
	return t.recvPubKeyInc(resp)
}

func (t *TPKT) recvPubKeyInc(data []byte) error {
	if err := t.ctx.Err(); err != nil {
		return nlaFailure(core.ErrKindTimeout, "NLA context ended", err)
	}
	glog.Trace("recvPubKeyInc", hex.EncodeToString(data))
	tsreq, err := nla.DecodeDERTRequest(data)
	if err != nil {
		glog.Info("DecodeDERTRequest", err)
		return nlaFailure(core.ErrKindProtocol, "decode NLA pubkey response", err)
	}
	if err := credSSPStatus(tsreq.ErrorCode); err != nil {
		return err
	}
	if len(tsreq.PubKeyAuth) <= 16 {
		return nlaFailure(core.ErrKindProtocol, "missing or truncated NLA public-key binding", nil)
	}
	glog.Trace("PubKeyAuth:", tsreq.PubKeyAuth)

	if t.VerifyServer && len(tsreq.PubKeyAuth) > 0 {
		serverPubKey := t.ntlmSec.GssDecrypt([]byte(tsreq.PubKeyAuth))
		origPubKey, pkErr := t.Conn.TlsPubKey()
		if pkErr != nil {
			return nlaFailure(core.ErrKindTLS, "read TLS server public key", pkErr)
		}
		// Server should return the public key with first byte incremented by 1
		expected := make([]byte, len(origPubKey))
		copy(expected, origPubKey)
		if len(expected) > 0 {
			expected[0]++
		}
		if len(serverPubKey) != len(expected) {
			return nlaFailure(core.ErrKindProtocol, "server PubKeyAuth verification failed: length mismatch", nil)
		}
		match := true
		for i := range serverPubKey {
			if serverPubKey[i] != expected[i] {
				match = false
				break
			}
		}
		if !match {
			return nlaFailure(core.ErrKindProtocol, "server PubKeyAuth verification failed: possible MITM", nil)
		}
		glog.Debug("Server PubKeyAuth verified successfully")
	}

	domain, username, password := t.ntlm.GetEncodedCredentials()
	credentials := nla.EncodeDERTCredentials(domain, username, password)
	authInfo := t.ntlmSec.GssEncrypt(credentials)
	req := nla.EncodeDERTRequest(nil, authInfo, nil)
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send AuthenticateMessage", err)
		return nlaFailure(core.ErrKindNetwork, "send NLA credentials", err)
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
			// A short-length fastpath packet carries the total length in the
			// second byte; a value below the 3-byte minimum (action + length
			// + payload) is malformed. Reading lastShortLength-2 for such a
			// frame used to panic the process ("makeslice: len out of range",
			// issue x90skysn3k/brutespray#366) — report it instead.
			if t.lastShortLength < 3 {
				glog.Error("TPTK recvHeader: malformed fastpath short length", t.lastShortLength)
				t.Emit("error", fmt.Errorf("tpkt: malformed fastpath short length %d", t.lastShortLength))
				return
			}
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
	// TPKT total length includes its 4-byte header; anything smaller is a
	// malformed frame and the size-4 read used to panic the process.
	if size < 4 {
		glog.Error("TPTK recvExtendedHeader: malformed TPKT length", size)
		t.Emit("error", fmt.Errorf("tpkt: malformed TPKT length %d", size))
		return
	}
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
	// Extended-length fastpath packets have a 3-byte header; a declared size
	// below it used to panic the process via the packetSize-3 read.
	if packetSize < 3 {
		glog.Error("TPTK recvExtendedFastPathHeader: malformed fastpath length", packetSize)
		t.Emit("error", fmt.Errorf("tpkt: malformed fastpath length %d", packetSize))
		return
	}
	core.StartReadBytes(t.ctx, packetSize-3, t.Conn, t.recvFastPath)
}

func (t *TPKT) recvFastPath(s []byte, err error) {
	glog.Trace("tpkt recvFastPath")
	if err != nil {
		return
	}

	// The auth-only login flow (LoginAuthOnly) never builds the SEC/PDU
	// stack, so no FastPath listener is ever registered, yet tpkt.New has
	// already started this read loop. Servers that push FastPath output
	// right after the CredSSP handshake would hit a nil interface method
	// call here and crash the whole process (this goroutine has no
	// recover). Discard the frame and keep reading instead.
	if t.fastPathListener == nil {
		glog.Trace("tpkt recvFastPath: no fast path listener, dropping frame")
		core.StartReadBytes(t.ctx, 2, t.Conn, t.recvHeader)
		return
	}

	t.fastPathListener.RecvFastPath(t.secFlag, s)
	core.StartReadBytes(t.ctx, 2, t.Conn, t.recvHeader)
}
