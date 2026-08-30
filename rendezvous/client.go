package rendezvous

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Session is a client's handle on a session at the rendezvous.
//
// Its two useful methods return a net.Conn and a net.Listener, which is
// deliberate: the ring already speaks those, so a relayed path and a direct one
// are interchangeable and nothing above this package has to know which it got.
// It is also what lets hole punching arrive later without touching the ring.
type Session struct {
	Addr    string // rendezvous address
	ID      string
	Code    string
	PeerID  string
	Model   string
	Members int

	control net.Conn
}

// greet opens a connection and exchanges the first message.
//
// The reply is decoded with a json.Decoder, which reads ahead, so whatever it
// buffered past the reply has to be handed to the caller rather than dropped.
// For host and join nothing follows, but for dial and accept the peer's very
// first bytes can already be sitting in that buffer, and losing them corrupts
// the stream in a way that surfaces much later as a malformed frame.
// A timeout of zero dials without one, for a parked accept: it waits until a
// peer arrives, which is the whole point of parking it.
func greet(addr string, h Hello, timeout time.Duration) (net.Conn, *Welcome, io.Reader, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("rendezvous: dial %s: %w", addr, err)
	}

	// The timeout has to cover the reply, not just the connection.
	//
	// Reaching the rendezvous is the quick part. A dial is then *parked* until
	// the peer it names accepts, so the welcome does not arrive until the two
	// ends have been paired -- which, for a peer that has crashed or is not
	// listening, is never. Bounding only the TCP connect left the caller waiting
	// on that indefinitely while holding a timeout it had every reason to
	// believe applied.
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	c, w, rest, err := handshake(conn, h)
	if err != nil {
		return nil, nil, nil, err
	}

	// Cleared before the connection is handed over. A deadline left on it would
	// expire under whoever reads it next, and the failure -- reads that stop
	// working on a connection that was fine a moment ago -- looks like the
	// network rather than like a leftover.
	_ = c.SetDeadline(time.Time{})
	return c, w, rest, nil
}

// handshake performs the greeting on a connection the caller already holds, so
// a parked accept can be aborted by closing it from underneath.
func handshake(conn net.Conn, h Hello) (net.Conn, *Welcome, io.Reader, error) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	if err := json.NewEncoder(conn).Encode(h); err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("rendezvous: greet: %w", err)
	}

	dec := json.NewDecoder(conn)
	var w Welcome
	if err := dec.Decode(&w); err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("rendezvous: no reply: %w", err)
	}
	if !w.OK {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("rendezvous: %s", w.Error)
	}

	// What the decoder read ahead is the peer's first bytes, and dropping it
	// corrupts the stream. But the very first of those bytes is not payload:
	// json.Encoder.Encode writes exactly one newline after the value and Decode
	// does not consume it, so it has to be eaten here or it arrives at the far
	// end as a stray byte in front of the first frame.
	//
	// Read it from the chained reader rather than from the decoder's buffer,
	// because whether the newline made it into that buffer depends on how the
	// bytes happened to arrive.
	rest := io.MultiReader(dec.Buffered(), conn)
	var nl [1]byte
	if _, err := io.ReadFull(rest, nl[:]); err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("rendezvous: truncated reply: %w", err)
	}
	if nl[0] != '\n' {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("rendezvous: reply not newline-terminated (got %q)", nl[0])
	}
	return conn, &w, rest, nil
}

// Host opens a session and returns the code others use to join.
func Host(addr, model string, members int, label string) (*Session, error) {
	return HostWith(addr, model, members, label, nil)
}

// HostWith opens a session and records what the host itself can carry, so the
// planner sees every machine the same way including its own.
func HostWith(addr, model string, members int, label string, capability []byte) (*Session, error) {
	conn, w, _, err := greet(addr, Hello{
		Op: "host", Model: model, Members: members, Label: label, Capability: capability,
	}, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return &Session{
		Addr: addr, ID: w.Session, Code: w.Code, PeerID: w.PeerID,
		Model: w.Model, Members: w.Members, control: conn,
	}, nil
}

// Join attaches to a session by its code.
func Join(addr, code, label string) (*Session, error) {
	return JoinWith(addr, code, label, nil)
}

// JoinWith attaches and tells the host what this machine can carry. The blob is
// opaque to the rendezvous and reaches the host untouched.
func JoinWith(addr, code, label string, capability []byte) (*Session, error) {
	conn, w, _, err := greet(addr, Hello{
		Op: "join", Code: code, Label: label, Capability: capability,
	}, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return &Session{
		Addr: addr, ID: w.Session, PeerID: w.PeerID,
		Model: w.Model, Members: w.Members, control: conn,
	}, nil
}

func (s *Session) Close() error {
	if s.control == nil {
		return nil
	}
	return s.control.Close()
}

// Dial opens a stream to another peer in the session.
//
// It blocks until that peer is accepting. A ring's nodes load hundreds of
// megabytes before they are ready, so arriving first is the normal case rather
// than an error, and a short timeout here would turn ordinary startup skew into
// a failure.
func (s *Session) Dial(to string, timeout time.Duration) (net.Conn, error) {
	return s.DialStream(to, "", timeout)
}

// DialStream opens a stream to one of a peer's named listeners.
//
// A peer keeps more than one listener open at a time, and the name is how the
// rendezvous tells them apart. Dial the wrong one and the connection still
// forms: the bytes simply arrive somewhere that was not expecting them, which
// no error anywhere will report.
func (s *Session) DialStream(to, stream string, timeout time.Duration) (net.Conn, error) {
	conn, _, buffered, err := greet(s.Addr, Hello{
		Op: "dial", Session: s.ID, From: s.PeerID, To: to, Stream: stream,
	}, timeout)
	if err != nil {
		return nil, err
	}
	return &peerConn{Conn: conn, r: buffered, remote: to}, nil
}

// Listen returns a listener that accepts streams other peers open to us.
//
// It keeps several accepts parked at the rendezvous at all times, which is what
// a TCP listener gets for free from the kernel's backlog. That is not a detail:
// a ring node listens and then dials, and every node does both, so if an accept
// only reached the rendezvous when the application called Accept, every node
// would be blocked dialling a peer that had not accepted yet and the ring would
// never close. A direct transport hides this, because the kernel completes the
// handshake whether or not anyone has called Accept.
func (s *Session) Listen() net.Listener { return s.ListenStream("") }

// ListenStream accepts the streams opened to this peer under one name.
//
// Every listener a peer opens needs its own name. Two on the same name share a
// queue at the rendezvous, and a dial is then answered by whichever of them
// reaches the front — including one whose owner has stopped reading it.
func (s *Session) ListenStream(stream string) net.Listener {
	l := &relayListener{
		s:      s,
		stream: stream,
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
	for range listenBacklog {
		go l.park()
	}
	return l
}

// listenBacklog is how many accepts wait at the rendezvous at once. A ring node
// needs one; the spare covers the moment between handing one over and parking
// the next, so a peer dialling in that window is not left waiting.
const listenBacklog = 2

type relayListener struct {
	s      *Session
	stream string
	conns  chan net.Conn
	once   sync.Once
	closed chan struct{}

	mu     sync.Mutex
	parked map[net.Conn]struct{}
}

// park keeps one accept waiting at the rendezvous, hands over whatever arrives,
// and immediately waits again.
func (l *relayListener) park() {
	for {
		select {
		case <-l.closed:
			return
		default:
		}

		raw, err := net.DialTimeout("tcp", l.s.Addr, 15*time.Second)
		if err == nil && !l.track(raw) {
			// Closed while we were dialling.
			raw.Close()
			return
		}
		if err == nil {
			// Registered before the greeting, so Close can cut it short. A
			// parked accept blocks in a read at the rendezvous and cannot
			// notice a closed channel; without this, closing a listener leaves
			// its accepts registered, and the next peer to dial this node gets
			// spliced to a connection nobody is reading. That is not a leak
			// that shows up as a leak — it is a ring that forms and then hangs
			// on the first frame.
			_ = raw
		}
		var buffered io.Reader
		var conn net.Conn
		if err == nil {
			conn, _, buffered, err = handshake(raw, Hello{
				Op: "accept", Session: l.s.ID, To: l.s.PeerID, Stream: l.stream,
			})
		}
		if err != nil {
			if raw != nil {
				l.untrack(raw)
				raw.Close()
			}
			// The rendezvous may be briefly unavailable, or this listener may
			// have been closed underneath us. Neither is worth spinning on.
			select {
			case <-l.closed:
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}

		l.untrack(raw)
		select {
		case l.conns <- &peerConn{Conn: conn, r: buffered, remote: "peer"}:
		case <-l.closed:
			conn.Close()
			return
		}
	}
}

// track registers a connection so Close can cancel it, and reports whether the
// listener is still open.
//
// The closed check has to happen under the same lock as the registration. A
// park goroutine that dialled while Close was running would otherwise register
// afterwards, re-create the map Close had just emptied, and leave an accept
// waiting at the rendezvous for a listener nobody is reading. The next peer to
// dial this node is then spliced to it, and the ring forms and hangs on its
// first frame with no error anywhere.
func (l *relayListener) track(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
	}
	if l.parked == nil {
		l.parked = map[net.Conn]struct{}{}
	}
	l.parked[c] = struct{}{}
	return true
}

func (l *relayListener) untrack(c net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.parked, c)
}

// Accept returns a peer that has actually been spliced to us.
func (l *relayListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close stops accepting and cancels any accepts already waiting at the
// rendezvous, so this node stops being a destination the moment it says it has.
func (l *relayListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.mu.Lock()
		for c := range l.parked {
			c.Close()
		}
		l.parked = nil
		l.mu.Unlock()
	})
	return nil
}

func (l *relayListener) Addr() net.Addr { return relayAddr(l.s.PeerID) }

type relayAddr string

func (a relayAddr) Network() string { return "rendezvous" }
func (a relayAddr) String() string  { return string(a) }

// peerConn is a spliced stream whose reads are chained through whatever the
// greeting's decoder read ahead, so no byte of the peer's payload is lost and
// none of the greeting's framing is mistaken for payload.
//
// Writes and deadlines go to the connection unchanged; only Read is wrapped.
type peerConn struct {
	net.Conn
	r      io.Reader
	remote string
}

func (c *peerConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *peerConn) RemoteAddr() net.Addr { return relayAddr(c.remote) }

// Transport adapts a Session to what the ring needs to reach its neighbours.
//
// It is returned as its own type rather than having Session implement the
// interface directly, because the two Listen methods differ: this one reports an
// error, as a transport must. Nothing here imports the ring — Go's interfaces
// are structural, so satisfying agent.Transport needs no dependency in either
// direction.
type Transport struct {
	s      *Session
	stream string
}

func (s *Session) Transport() *Transport { return &Transport{s: s} }

// TransportFor is a transport whose listens and dials all name one stream, so
// a caller that already speaks net.Listener and net.Conn needs to know nothing
// about streams beyond choosing a name once.
func (s *Session) TransportFor(stream string) *Transport {
	return &Transport{s: s, stream: stream}
}

func (t *Transport) Listen() (net.Listener, error) { return t.s.ListenStream(t.stream), nil }

func (t *Transport) Dial(peer string, timeout time.Duration) (net.Conn, error) {
	return t.s.DialStream(peer, t.stream, timeout)
}

// Events reports session changes pushed by the rendezvous. Host connections
// receive them; a member's control connection stays quiet.
//
// The channel closes when the control connection does, which is how a caller
// waiting for members learns that the session has gone away rather than waiting
// out its timeout.
func (s *Session) Events() <-chan Event {
	out := make(chan Event, 8)
	go func() {
		defer close(out)
		dec := json.NewDecoder(s.control)
		for {
			var e Event
			if err := dec.Decode(&e); err != nil {
				return
			}
			out <- e
		}
	}()
	return out
}

// AwaitPeers blocks until the session holds n peers including this one, and
// returns their ids in join order with the host first.
//
// Join order is the order the ring will be wired in unless the planner says
// otherwise, and the host is first because it holds the head.
func (s *Session) AwaitPeers(n int, timeout time.Duration) ([]Event, error) {
	if n <= 1 {
		return nil, nil
	}
	events := s.Events()
	deadline := time.After(timeout)
	var joined []Event
	for len(joined) < n-1 {
		select {
		case e, ok := <-events:
			if !ok {
				return joined, fmt.Errorf("rendezvous: session ended with %d of %d peers", len(joined)+1, n)
			}
			if e.Kind == "joined" {
				joined = append(joined, e)
			}
		case <-deadline:
			return joined, fmt.Errorf("rendezvous: only %d of %d peers joined in time", len(joined)+1, n)
		}
	}
	return joined, nil
}
