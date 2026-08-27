package direct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// The ring speaks net.Listener and net.Conn and must not learn which kind of
// path it is on. That is what makes a direct edge and a relayed one
// interchangeable, and it is why the transport interface exists at all.
//
// QUIC has two levels — connections, and streams within them — where a
// net.Listener has one. Streams are flattened into a single queue here, so an
// Accept returns the next stream from any neighbour, exactly as an Accept on a
// TCP listener returns the next connection from anyone.

// Listen accepts streams opened to this node.
func (e *Endpoint) Listen() (net.Listener, error) { return &listener{e: e}, nil }

// Dial opens a stream to a peer by its session id.
//
// The QUIC connection underneath is made once and kept: a decode frame is about
// two kilobytes, and a handshake per token would make the handshake the thing
// being measured. Streams are cheap, which is the property §4 wanted from QUIC.
func (e *Endpoint) Dial(peer string, timeout time.Duration) (net.Conn, error) {
	e.mu.Lock()
	p, known := e.peers[peer]
	conn := e.conns[peer]
	e.mu.Unlock()

	if !known {
		return nil, fmt.Errorf("direct: no address known for %s", peer)
	}

	if conn == nil {
		var err error
		conn, err = e.connect(peer, p, timeout)
		if err != nil {
			return nil, err
		}
	}

	s, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		// The connection may have died while it was idle. Drop it so the next
		// attempt builds a new one rather than failing forever on a corpse.
		e.forget(peer, conn)
		return nil, fmt.Errorf("direct: open a stream to %s: %w", peer, err)
	}
	return &streamConn{Stream: s, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

func (e *Endpoint) connect(peer string, p Peer, timeout time.Duration) (*quic.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", p.Addr)
	if err != nil {
		return nil, fmt.Errorf("direct: address of %s (%q): %w", peer, p.Addr, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := e.tr.Dial(ctx, addr, e.clientTLS(p.Fingerprint), quicConfig())
	if err != nil {
		return nil, fmt.Errorf("direct: reach %s at %s: %w", peer, p.Addr, err)
	}

	// Not connected until the far side says so; see confirm.
	if err := confirm(conn, timeout); err != nil {
		_ = conn.CloseWithError(0, "not confirmed")
		return nil, fmt.Errorf("direct: %s did not accept us: %w", peer, err)
	}

	// Both ends may have dialled at once after a punch, in which case two
	// connections exist and either will do. Keep the first one recorded and
	// close the loser rather than leaving both alive, so a peer is reached the
	// same way in both directions.
	e.mu.Lock()
	if existing, ok := e.conns[peer]; ok && existing != nil {
		e.mu.Unlock()
		_ = conn.CloseWithError(0, "duplicate")
		return existing, nil
	}
	e.conns[peer] = conn
	e.mu.Unlock()
	return conn, nil
}

func (e *Endpoint) forget(peer string, conn *quic.Conn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conns[peer] == conn {
		delete(e.conns, peer)
	}
}

type listener struct{ e *Endpoint }

func (l *listener) Accept() (net.Conn, error) {
	select {
	case a := <-l.e.accepted:
		if a.err != nil {
			return nil, a.err
		}
		return &streamConn{Stream: a.stream, local: a.conn.LocalAddr(), remote: a.conn.RemoteAddr()}, nil
	case <-l.e.closed:
		return nil, net.ErrClosed
	}
}

func (l *listener) Close() error   { return nil } // the endpoint owns the socket
func (l *listener) Addr() net.Addr { return l.e.LocalAddr() }

// streamConn is a QUIC stream presented as a net.Conn.
//
// A stream carries Read, Write, Close and the deadlines already. What it does
// not carry is addresses, because in QUIC those belong to the connection rather
// than to the stream, so they are attached here.
type streamConn struct {
	*quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

// Close ends this stream in both directions.
//
// quic.Stream.Close only closes the write side — it says "I have finished
// sending" and leaves reading open, which is correct for a request/response
// exchange and wrong for a net.Conn, whose Close means the conversation is
// over. Without cancelling the read side too, a caller that closes a link
// leaves the peer's writes accepted into a stream nobody will ever read.
func (c *streamConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

var (
	_ net.Listener = (*listener)(nil)
	_ net.Conn     = (*streamConn)(nil)
)

// ErrNoPath is returned when an edge has no direct path and the caller should
// fall back to a relay rather than treat it as a failure.
var ErrNoPath = errors.New("direct: no path")
