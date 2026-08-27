// Package rendezvous lets machines behind NAT find each other and talk.
//
// The problem it solves is the first one a session hits. Today a host listens
// on a port and prints an address for members to dial, which requires the host
// to accept an unsolicited inbound connection. Behind NAT it cannot, so the
// session never forms: the member waits on "waiting for session host" and the
// host sees nothing. It only ever worked by carrying a public address between
// the two by hand.
//
// Here nobody accepts an inbound connection. Every participant dials *out* to
// one always-on service, which pairs them. That is the whole idea, and it is
// what makes the thing usable by people who will not configure a router.
//
// # What it does and does not change
//
// Block assignment is untouched: ranges stay contiguous and cover the model
// exactly once. A departing member still fails in-flight requests, exactly as
// before.
//
// It does add one exposure, and it is stated here rather than left to be found:
// while a path is relayed, hidden states pass through the rendezvous, and a
// hidden state is not opaque — it carries a great deal about the text that
// produced it. Direct paths are the fix and are the next increment, not an
// afterthought.
//
// # What this is not, yet
//
// Every byte is relayed. That is the simplest thing that makes a session form
// at all, and it is deliberately the first increment: it gets real sessions
// running between real people, which is what the measurements need. Hole
// punching to move paths off the relay comes next, and the interfaces here are
// shaped so that it slots in without the ring code noticing — a direct path and
// a relayed one are both just a net.Conn.
package rendezvous

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/kafila-research/protocol/reach"
)

// Hello is the first line a client sends. Everything after it, for dial and
// accept, is opaque bytes spliced to the other party.
type Hello struct {
	Op string `json:"op"` // host | join | dial | accept

	// host
	Model   string `json:"model,omitempty"`
	Members int    `json:"members,omitempty"`

	// join
	Code string `json:"code,omitempty"`

	// dial and accept
	Session string `json:"session,omitempty"`
	From    string `json:"from,omitempty"`
	// To names the accepting peer, for both ops: the acceptor says who it is,
	// the dialer says who it wants. Keying both on the acceptor is what lets
	// them meet.
	To string `json:"to,omitempty"`

	// Stream separates the listeners a peer keeps open at once, because a peer
	// is not one endpoint. A node accepts ring frames on one and, if it serves
	// the interface, HTTP on another; earlier it also took its assignment on a
	// third. Keyed on the peer alone they share a queue, so a dial is answered
	// by whichever listener happens to be at the front — the ring's frames go
	// to the HTTP server, or into a listener nobody reads, and the failure is
	// silent at both ends.
	//
	// Empty is a stream like any other, which is what the ring used before
	// there was a name for it.
	Stream string `json:"stream,omitempty"`

	Label string `json:"label,omitempty"`

	// Capability is whatever a member wants the host to know about it, passed
	// through untouched. The rendezvous has no business understanding working
	// sets or GPU flags, and keeping it opaque means the planner can change
	// what it asks for without this service changing at all.
	Capability json.RawMessage `json:"capability,omitempty"`
}

// Event is pushed to the host's control connection as the session changes.
//
// This is why that connection is long-lived. A host that polled for members
// would add its polling interval to every join, and a session that is assembling
// is exactly when people are watching it.
type Event struct {
	Kind       string          `json:"kind"` // joined | left
	PeerID     string          `json:"peerID"`
	Label      string          `json:"label,omitempty"`
	Capability json.RawMessage `json:"capability,omitempty"`
	Peers      int             `json:"peers"`
}

// Welcome is the reply to host and join.
type Welcome struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Session string `json:"session,omitempty"`
	Code    string `json:"code,omitempty"`
	PeerID  string `json:"peerID,omitempty"`
	Model   string `json:"model,omitempty"`
	Members int    `json:"members,omitempty"`
}

type member struct {
	ID         string
	Label      string
	Capability json.RawMessage
	// Observed is the address the connection arrived from, which is the only
	// address worth believing. A self-reported one is wrong behind NAT and a
	// lie from anyone hostile.
	Observed string
}

type session struct {
	mu      sync.Mutex
	ID      string
	Code    string
	Model   string
	Members int
	Peers   []member

	// control is the host's connection, held open so joins can be pushed.
	control net.Conn

	// waiting holds accept-side connections that have arrived before their
	// dialer, keyed by the accepting peer. A ring starts as several processes
	// at once and they do not arrive in order.
	waiting map[waitKey]chan net.Conn
}

// Server pairs machines that cannot accept connections.
type Server struct {
	mu       sync.Mutex
	sessions map[string]*session // by id
	byCode   map[string]*session

	ln    net.Listener
	reach *reach.Server
}

func NewServer() *Server {
	return &Server{sessions: map[string]*session{}, byCode: map[string]*session{}}
}

func newID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("rendezvous: no entropy: " + err.Error())
	}
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))
}

// newCode is the token a person types or pastes to join.
//
// It is a bearer token and the only access control the protocol has: whoever
// holds it can join, and a member sees every activation that passes through its
// shard. Short enough to read aloud, long enough that guessing is not a
// strategy — 40 bits from a crypto source. That it is the only access control
// is a limitation to be fixed, not a design.
func newCode() string { return newID(5) }

// Start binds and serves in the background, returning once the listener is up.
//
// Serve stores the listener, so a caller that backgrounds Serve and then asks
// for Addr races it and can get nothing back. Binding synchronously here
// removes the race rather than documenting it.
func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	go func() { _ = s.Serve(ln) }()
	return nil
}

// Serve runs until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	slog.Info("rendezvous listening", "address", ln.Addr())

	// Behaviour probes answer on UDP at the same port number and the one above.
	// A session already knows this address, so nothing has to be configured
	// twice and a member can measure its own network before it joins.
	//
	// This belongs here rather than in Start because Start is not the only way
	// in: the command line builds its own listener and calls Serve directly, so
	// putting it in Start meant the probes never bound at all — and the warning
	// that would have said so was in the path that never ran.
	//
	// Failing to bind is not fatal. The probe is instrumentation; a session
	// forms and serves without it, and losing the measurement is better than
	// losing the session.
	if rs, err := reach.Listen(ln.Addr().String()); err != nil {
		slog.Warn("behaviour probes unavailable; sessions will still form", "error", err)
	} else {
		s.mu.Lock()
		s.reach = rs
		s.mu.Unlock()
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *Server) Close() error {
	s.mu.Lock()
	ln, rs := s.ln, s.reach
	s.mu.Unlock()
	if rs != nil {
		rs.Close()
	}
	if ln == nil {
		return nil
	}
	return ln.Close()
}

func (s *Server) handle(conn net.Conn) {
	// The greeting must not hang a connection slot forever, but once a session
	// is established the connection is long-lived, so the deadline is cleared
	// rather than extended.
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	dec := json.NewDecoder(conn)
	var h Hello
	if err := dec.Decode(&h); err != nil {
		slog.Debug("rendezvous: bad greeting", "error", err)
		conn.Close()
		return
	}

	// Everything past the greeting belongs to the peer, and the greeting did
	// not necessarily stop where the JSON did. Two bytes go missing otherwise,
	// and neither failure looks like a parsing bug:
	//
	// Whatever the decoder read ahead is already out of the socket, so splicing
	// the raw connection drops it.
	//
	// And Encode writes a newline after the value that Decode does not consume.
	// If it is still in the socket it gets spliced to the peer as a stray byte
	// in front of the first frame — which shifts the frame header by one, gives
	// a length nobody sent, and leaves the reader blocked forever on bytes that
	// are never coming. No error is raised at either end and both sides go on
	// believing they are connected, so it surfaces as a ring that forms, aligns,
	// and then hangs on the first real frame.
	greeted, err := settle(conn, dec)
	if err != nil {
		slog.Debug("rendezvous: bad greeting", "error", err)
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	conn = greeted

	observed := ""
	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		observed = host
	}

	switch h.Op {
	case "host":
		s.doHost(conn, h, observed)
	case "join":
		s.doJoin(conn, h, observed)
	case "dial":
		s.doDial(conn, h)
	case "accept":
		s.doAccept(conn, h)
	default:
		writeJSON(conn, Welcome{Error: "unknown op " + h.Op})
		conn.Close()
	}
}

func writeJSON(w io.Writer, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("rendezvous: write reply", "error", err)
	}
}

func (s *Server) doHost(conn net.Conn, h Hello, observed string) {
	if h.Model == "" || h.Members < 1 {
		writeJSON(conn, Welcome{Error: "host needs a model and a member count"})
		conn.Close()
		return
	}

	sess := &session{
		ID: newID(8), Code: newCode(), Model: h.Model, Members: h.Members,
		waiting: map[waitKey]chan net.Conn{},
	}
	hostID := newID(4)
	sess.Peers = append(sess.Peers, member{
		ID: hostID, Label: h.Label, Observed: observed, Capability: h.Capability,
	})
	sess.control = conn

	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.byCode[sess.Code] = sess
	s.mu.Unlock()

	slog.Info("session opened", "session", sess.ID, "code", sess.Code,
		"model", sess.Model, "members", sess.Members)
	writeJSON(conn, Welcome{
		OK: true, Session: sess.ID, Code: sess.Code, PeerID: hostID,
		Model: sess.Model, Members: sess.Members,
	})
	// The control connection stays open for the session's lifetime so the
	// rendezvous can push — a member joining, a departure — without the host
	// polling and adding its interval to every join.
}

func (s *Server) doJoin(conn net.Conn, h Hello, observed string) {
	s.mu.Lock()
	sess := s.byCode[strings.ToLower(strings.TrimSpace(h.Code))]
	s.mu.Unlock()
	if sess == nil {
		writeJSON(conn, Welcome{Error: "no session with that code"})
		conn.Close()
		return
	}

	sess.mu.Lock()
	id := newID(4)
	sess.Peers = append(sess.Peers, member{
		ID: id, Label: h.Label, Observed: observed, Capability: h.Capability,
	})
	n := len(sess.Peers)
	control := sess.control
	sess.mu.Unlock()

	slog.Info("member joined", "session", sess.ID, "peer", id, "label", h.Label, "peers", n)

	// Tell the host, so it can plan as soon as the last member arrives rather
	// than on the next tick of something.
	if control != nil {
		writeJSON(control, Event{
			Kind: "joined", PeerID: id, Label: h.Label,
			Capability: h.Capability, Peers: n,
		})
	}
	writeJSON(conn, Welcome{
		OK: true, Session: sess.ID, PeerID: id,
		Model: sess.Model, Members: sess.Members,
	})
}

// Peers reports who is in a session, for the host's planner.
func (s *Server) Peers(sessionID string) []string {
	s.mu.Lock()
	sess := s.sessions[sessionID]
	s.mu.Unlock()
	if sess == nil {
		return nil
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	out := make([]string, 0, len(sess.Peers))
	for _, p := range sess.Peers {
		out = append(out, p.ID)
	}
	return out
}

// doAccept parks a connection until somebody dials the peer it belongs to.
func (s *Server) doAccept(conn net.Conn, h Hello) {
	s.mu.Lock()
	sess := s.sessions[h.Session]
	s.mu.Unlock()
	if sess == nil {
		writeJSON(conn, Welcome{Error: "no such session"})
		conn.Close()
		return
	}

	// Keyed on the acceptor, which is what the dialer will ask for. No reply is
	// sent yet: the client's Accept must not return a connection that is only
	// parked, so the acknowledgement is written at splice time instead. That is
	// what gives Accept the blocking semantics a net.Listener is supposed to
	// have.
	sess.mu.Lock()
	key := waitKey{peer: h.To, stream: h.Stream}
	ch, ok := sess.waiting[key]
	if !ok {
		ch = make(chan net.Conn, 1)
		sess.waiting[key] = ch
	}
	sess.mu.Unlock()

	select {
	case ch <- conn:
		// Parked. doDial will take it and splice.
	case <-time.After(10 * time.Minute):
		conn.Close()
	}
}

// doDial finds the parked accept side and splices the two together.
func (s *Server) doDial(conn net.Conn, h Hello) {
	s.mu.Lock()
	sess := s.sessions[h.Session]
	s.mu.Unlock()
	if sess == nil {
		writeJSON(conn, Welcome{Error: "no such session"})
		conn.Close()
		return
	}

	sess.mu.Lock()
	key := waitKey{peer: h.To, stream: h.Stream}
	ch, ok := sess.waiting[key]
	if !ok {
		ch = make(chan net.Conn, 1)
		sess.waiting[key] = ch
	}
	sess.mu.Unlock()

	// A ring's nodes load hundreds of megabytes before they are ready, so the
	// dialer routinely arrives well before the acceptor. Waiting is normal
	// here, not an error.
	//
	// A parked connection can also be dead by the time it is claimed: a peer
	// that closed a listener cancels its accepts, but any it had already
	// registered are sitting here. Splicing to one produces a ring that forms
	// and then hangs on its first frame, with nothing anywhere reporting an
	// error, so the acknowledgement is used as the liveness check — if it
	// cannot be delivered, that peer is gone and the next one is tried.
	var peer net.Conn
	deadline := time.After(10 * time.Minute)
	for {
		select {
		case peer = <-ch:
		case <-deadline:
			writeJSON(conn, Welcome{Error: "nobody accepted"})
			conn.Close()
			return
		}
		if !parkedAcceptIsAlive(peer) {
			slog.Debug("rendezvous: discarding a dead parked accept",
				"session", h.Session, "to", h.To, "stream", h.Stream)
			peer.Close()
			continue
		}
		if err := json.NewEncoder(peer).Encode(Welcome{OK: true}); err != nil {
			peer.Close()
			continue
		}
		break
	}

	// Both sides learn they are connected at the same moment, and only then.
	writeJSON(conn, Welcome{OK: true})
	slog.Debug("rendezvous: relaying",
		"session", h.Session, "from", h.From, "to", h.To, "stream", h.Stream)
	splice(conn, peer, h.From, h.To)
}

// waitKey is what a dial and an accept must agree on to be paired: which peer,
// and which of that peer's listeners.
type waitKey struct {
	peer   string
	stream string
}

// parkedAcceptIsAlive reports whether a waiting acceptor is still there.
//
// Reading is the test rather than writing. A parked acceptor is blocked waiting
// for its acknowledgement and sends nothing, so a read times out while it is
// alive and returns end-of-file the moment it has gone. Writing cannot tell the
// difference: a write to a peer that has just closed usually succeeds, sitting
// in the send buffer while the reset is still in flight, so the dead connection
// passes the test and gets spliced to a ring that then hangs on its first frame.
//
// The wait is short and is paid once per edge, when it is set up.
func parkedAcceptIsAlive(c net.Conn) bool {
	if err := c.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		return false
	}
	defer c.SetReadDeadline(time.Time{}) //nolint:errcheck // best effort; the splice sets its own

	var probe [1]byte
	_, err := c.Read(probe[:])
	if err == nil {
		// An acceptor that is talking before it has been introduced is not one
		// of ours, whatever else it is.
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// splice copies bytes both ways until either side goes away.
//
// Everything above this point is control; from here the rendezvous is a pipe
// and does not look at what passes through. It could: hidden states are not
// opaque. That is the cost of relaying and the reason direct paths matter.
// settle hands back the connection with its reads chained through whatever the
// greeting's decoder buffered, having consumed the newline Encode wrote after
// the value. The mirror of this lives in the client's handshake.
func settle(conn net.Conn, dec *json.Decoder) (net.Conn, error) {
	rest := io.MultiReader(dec.Buffered(), conn)
	var nl [1]byte
	if _, err := io.ReadFull(rest, nl[:]); err != nil {
		return nil, fmt.Errorf("rendezvous: truncated greeting: %w", err)
	}
	if nl[0] != '\n' {
		return nil, fmt.Errorf("rendezvous: greeting not newline-terminated (got %q)", nl[0])
	}
	return &greetedConn{Conn: conn, r: rest}, nil
}

// greetedConn is a connection whose reads start with what the greeting's
// decoder read ahead. It keeps the underlying connection reachable so the
// relay can still set socket options on it.
type greetedConn struct {
	net.Conn
	r io.Reader
}

func (c *greetedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *greetedConn) underlying() net.Conn       { return c.Conn }

// tcpOf digs out the socket under any wrapping, so socket options are not
// silently skipped on a connection that has been wrapped.
func tcpOf(c net.Conn) *net.TCPConn {
	for {
		switch v := c.(type) {
		case *net.TCPConn:
			return v
		case interface{ underlying() net.Conn }:
			c = v.underlying()
		default:
			return nil
		}
	}
}

// splice joins a dialer to the accept that was parked for it and copies until
// both directions are done. The two peer ids name the directions, so a log line
// says which way bytes stopped moving.
func splice(dialer, acceptor net.Conn, from, to string) {
	// A ring link is one-way: the head writes to the tail and never reads from
	// that connection. The unused direction therefore sits idle for as long as
	// the session is idle, and a relayed hop can sit behind a VPN or a NAT that
	// drops a flow it has not seen traffic on. Keepalives are what stop an idle
	// direction from being reclaimed underneath a link that is perfectly alive.
	keepAlive(dialer)
	keepAlive(acceptor)

	type ended struct {
		from, to string
		bytes    int64
		err      error
	}
	done := make(chan ended, 2)
	cp := func(from, to string, dst, src net.Conn) {
		n, err := relay(dst, src)
		// Propagate the half-close rather than tearing the pair down: the peer
		// that stopped writing has said so, and the other direction may still
		// have a whole response to carry.
		if tcp := tcpOf(dst); tcp != nil {
			_ = tcp.CloseWrite()
		}
		done <- ended{from, to, n, err}
	}
	go cp(from, to, acceptor, dialer)
	go cp(to, from, dialer, acceptor)

	// Both directions, not the first to finish. Closing on the first is what
	// let an idle direction timing out take a working one down with it.
	for range 2 {
		e := <-done
		slog.Debug("rendezvous: relay direction ended",
			"from", e.from, "to", e.to, "bytes", e.bytes, "error", e.err)
	}
	dialer.Close()
	acceptor.Close()
}

// relay copies one direction, accounting for every chunk.
//
// io.Copy would be shorter, but it consults the interfaces a connection
// happens to satisfy: a wrapped connection inherits ReadFrom and WriteTo from
// the socket it embeds, and io.Copy would then read the socket directly and
// step straight past the bytes the greeting's decoder had already taken out of
// it. Doing the loop here means the reads go through whatever Read the caller
// gave us, and it makes each chunk visible.
func relay(dst, src net.Conn) (int64, error) {
	buf := make([]byte, 64*1024)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, rerr
		}
	}
}

// keepAlive turns on TCP keepalives at an interval short enough to hold NAT and
// VPN state open on an idle link.
func keepAlive(c net.Conn) {
	tcp := tcpOf(c)
	if tcp == nil {
		return
	}
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(30 * time.Second)
}
