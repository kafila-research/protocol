// Package direct carries session traffic between two members over a path that
// touches nobody else.
//
// A relayed edge always works and always costs: every hidden state leaves both
// machines, crosses a third one, and arrives having been copied twice. This is
// the other option — one hop, and the rendezvous involved only in introducing
// the two ends.
//
// # One socket
//
// Everything here runs on a single UDP socket per node, and that is a
// requirement rather than a tidiness. A NAT mapping belongs to a source tuple,
// so the external address a peer is told to aim at describes one specific
// socket. Probing on one and sending on another measures a mapping the data
// never travels over, and on an address-dependent NAT the two differ by
// construction.
//
// quic-go is used because a quic.Transport binds a net.PacketConn we own and
// will both dial and accept on it. After a hole punch either end may
// legitimately be the initiator — whichever packet crosses first wins — so a
// socket that could only dial would throw away half the successful punches.
package direct

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// alpn names this protocol in the TLS handshake. QUIC requires one, and naming
// it rather than borrowing another protocol's means a stray connection from
// something else is refused during the handshake instead of at the first frame.
const alpn = "kafila/1"

// hello is the byte exchanged on a connection's first stream, and ack answers
// it. See confirm: it is how a dial learns it was accepted.
const (
	hello = 0x6b
	ack   = 0x61
)

// Identity is what a node proves it is on a direct path.
//
// QUIC mandates TLS, and there is no certificate authority here to ask: the
// members of a session are strangers' laptops. So each node makes its own key
// at startup and is known by a fingerprint of it, which the rendezvous carries
// to the others as part of the capability it already publishes. Each end then
// accepts exactly one fingerprint on that edge.
//
// This is deliberately stronger than the relayed path it replaces. A relayed
// edge is gated by the rendezvous — a peer has to hold the session id and the
// peer id to be paired with anyone — but a UDP socket on the open internet has
// no such gate, and a direct path that anyone could speak into would be a
// downgrade dressed as an optimisation.
type Identity struct {
	cert tls.Certificate

	// Fingerprint is a SHA-256 of the public key, base64url without padding.
	// It names the key rather than the certificate, so the certificate can be
	// reissued without the peer having to be told again.
	Fingerprint string
}

// NewIdentity mints a key for this process. It is ephemeral on purpose: a
// session is a bounded, socially formed thing, and an identity that outlived it
// would be a tracking handle nobody asked for.
func NewIdentity() (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("direct: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("direct: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "kafila-session-member"},
		// Not before "now": clocks between consumer machines disagree by more
		// than a handshake takes, and a certificate that is not yet valid at the
		// far end fails in a way that looks like a network fault.
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("direct: self-sign: %w", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("direct: marshal public key: %w", err)
	}
	sum := sha256.Sum256(spki)

	return &Identity{
		cert:        tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		Fingerprint: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// fingerprintOf names the key inside a presented certificate, the same way
// NewIdentity names its own.
func fingerprintOf(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Peer is where a member is and which key is allowed to answer for it.
type Peer struct {
	// Addr is the UDP address to aim at: the reflexive address the rendezvous
	// saw, or a local one when both ends share a network.
	Addr string

	// Fingerprint is the only key this edge will accept.
	Fingerprint string
}

// Endpoint is this node's whole data plane: one socket, one QUIC transport, and
// whatever connections it has to its neighbours.
type Endpoint struct {
	id *Identity
	tr *quic.Transport
	ln *quic.Listener

	mu    sync.Mutex
	peers map[string]Peer       // peer id -> where and who
	conns map[string]*quic.Conn // peer id -> live connection

	accepted chan acceptedStream
	closed   chan struct{}
	once     sync.Once
}

type acceptedStream struct {
	conn   *quic.Conn
	stream *quic.Stream
	err    error
}

// New takes ownership of a socket and starts accepting on it.
//
// The socket is the caller's to choose because it is the same one the
// reachability probe measured and the same one the punch will have opened. That
// is the whole reason this takes a PacketConn rather than an address.
func New(pc net.PacketConn, id *Identity, peers map[string]Peer) (*Endpoint, error) {
	if id == nil {
		return nil, errors.New("direct: an endpoint needs an identity")
	}
	e := &Endpoint{
		id:       id,
		tr:       &quic.Transport{Conn: pc},
		peers:    map[string]Peer{},
		conns:    map[string]*quic.Conn{},
		accepted: make(chan acceptedStream),
		closed:   make(chan struct{}),
	}
	for k, v := range peers {
		e.peers[k] = v
	}

	ln, err := e.tr.Listen(e.serverTLS(), quicConfig())
	if err != nil {
		return nil, fmt.Errorf("direct: listen: %w", err)
	}
	e.ln = ln
	go e.acceptConns()
	return e, nil
}

// LocalAddr is the socket everything here rides on.
func (e *Endpoint) LocalAddr() net.Addr { return e.tr.Conn.LocalAddr() }

// Learn records where a peer is and which key answers for it. Punching finds
// addresses after the endpoint exists, so this is not fixed at construction.
func (e *Endpoint) Learn(id string, p Peer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.peers[id] = p
}

// serverTLS accepts any client certificate and then insists it is one of the
// keys this session was told about.
//
// InsecureSkipVerify is not a weakening here — there is no chain to build,
// because there is no authority. The check it would perform is replaced by a
// stricter one: not "signed by someone reputable" but "this exact key".
func (e *Endpoint) serverTLS() *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{e.id.cert},
		NextProtos:            []string{alpn},
		ClientAuth:            tls.RequireAnyClientCert,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: e.verifyKnownPeer,
		MinVersion:            tls.VersionTLS13,
	}
}

// clientTLS pins one fingerprint: the peer we meant to reach, and nobody who
// happens to answer at that address.
func (e *Endpoint) clientTLS(want string) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{e.id.cert},
		NextProtos:         []string{alpn},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			return expectFingerprint(raw, want)
		},
	}
}

// verifyKnownPeer allows any key the session published. The accepting side does
// not know which neighbour is calling until it has looked, so it cannot pin one
// fingerprint the way the dialling side can.
func (e *Endpoint) verifyKnownPeer(raw [][]byte, _ [][]*x509.Certificate) error {
	if len(raw) == 0 {
		return errors.New("direct: peer presented no certificate")
	}
	got, err := fingerprintOf(raw[0])
	if err != nil {
		return fmt.Errorf("direct: unreadable peer certificate: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range e.peers {
		if p.Fingerprint == got {
			return nil
		}
	}
	return fmt.Errorf("direct: %s is not a key in this session", got)
}

func expectFingerprint(raw [][]byte, want string) error {
	if len(raw) == 0 {
		return errors.New("direct: peer presented no certificate")
	}
	got, err := fingerprintOf(raw[0])
	if err != nil {
		return fmt.Errorf("direct: unreadable peer certificate: %w", err)
	}
	if got != want {
		return fmt.Errorf("direct: answered by %s, expected %s", got, want)
	}
	return nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		// A ring link is idle between requests and must not be reclaimed for
		// being quiet; the relayed path needed TCP keepalives for the same
		// reason.
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  2 * time.Minute,
	}
}

// acceptConns takes inbound connections and fans their streams into one queue,
// so a caller sees a net.Listener rather than QUIC's two-level shape.
func (e *Endpoint) acceptConns() {
	for {
		conn, err := e.ln.Accept(context.Background())
		if err != nil {
			select {
			case <-e.closed:
			default:
				e.deliver(acceptedStream{err: err})
			}
			return
		}
		go e.acceptStreams(conn)
	}
}

func (e *Endpoint) acceptStreams(conn *quic.Conn) {
	// The first stream on a connection is the confirmation, not payload. It is
	// answered here and never surfaced, so a caller holding the listener sees
	// only real streams.
	first, err := conn.AcceptStream(context.Background())
	if err != nil {
		return
	}
	if err := answerConfirm(first); err != nil {
		_ = conn.CloseWithError(0, "confirmation failed")
		return
	}

	for {
		s, err := conn.AcceptStream(context.Background())
		if err != nil {
			return // this connection is done; others are unaffected
		}
		e.deliver(acceptedStream{conn: conn, stream: s})
	}
}

// answerConfirm completes the exchange the dialler is waiting on.
func answerConfirm(s *quic.Stream) error {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	var b [1]byte
	if _, err := io.ReadFull(s, b[:]); err != nil {
		return err
	}
	if b[0] != hello {
		return fmt.Errorf("direct: first stream opened with %#x, not a greeting", b[0])
	}
	_, err := s.Write([]byte{ack})
	return err
}

// confirm makes a dial mean what a caller will assume it means.
//
// TLS 1.3 sends the client certificate in the client's last flight, so the
// client's handshake completes before the server has looked at it. quic-go
// hands back a connection at that point, and a peer that is about to refuse the
// key has not refused it yet. Returning that connection to the ring would put
// the rejection somewhere far away — a write failing inside a forward pass —
// which is the shape of failure this project has already paid for once.
//
// One round trip per connection, not per stream, and a connection is made once
// per edge. That is a price worth paying to have a dial that either worked or
// returned an error.
func confirm(conn *quic.Conn, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("direct: open the confirming stream: %w", err)
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(timeout))

	if _, err := s.Write([]byte{hello}); err != nil {
		return fmt.Errorf("direct: greet: %w", err)
	}
	var b [1]byte
	if _, err := io.ReadFull(s, b[:]); err != nil {
		return fmt.Errorf("direct: the peer did not accept us: %w", err)
	}
	if b[0] != ack {
		return fmt.Errorf("direct: the peer answered %#x, not an acknowledgement", b[0])
	}
	return nil
}

func (e *Endpoint) deliver(a acceptedStream) {
	select {
	case e.accepted <- a:
	case <-e.closed:
	}
}

// Close stops accepting and drops every connection.
func (e *Endpoint) Close() error {
	e.once.Do(func() { close(e.closed) })
	if e.ln != nil {
		_ = e.ln.Close()
	}
	return e.tr.Close()
}
