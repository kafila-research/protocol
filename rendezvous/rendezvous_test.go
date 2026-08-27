package rendezvous

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func start(t *testing.T) *Server {
	t.Helper()
	s := NewServer()
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// The whole point of the package: a session forms without anyone accepting an
// unsolicited inbound connection. Both sides dial out.
func TestHostAndJoinWithoutListening(t *testing.T) {
	s := start(t)

	host, err := Host(s.Addr(), "qwen", 2, "host-machine")
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	defer host.Close()
	if host.Code == "" {
		t.Fatal("no join code issued")
	}

	member, err := Join(s.Addr(), host.Code, "friend-machine")
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	defer member.Close()

	if member.ID != host.ID {
		t.Errorf("member joined session %q, host opened %q", member.ID, host.ID)
	}
	if member.Model != "qwen" {
		t.Errorf("member was told model %q, want qwen", member.Model)
	}
	if member.PeerID == host.PeerID {
		t.Error("host and member were given the same peer id")
	}
	if got := s.Peers(host.ID); len(got) != 2 {
		t.Errorf("session has %d peers, want 2", len(got))
	}
}

func TestJoinRejectsAnUnknownCode(t *testing.T) {
	s := start(t)
	if _, err := Join(s.Addr(), "nosuchcode", "x"); err == nil {
		t.Fatal("joined a session that does not exist")
	}
}

// A stream between two peers, neither of which listens.
func TestPeersExchangeBytesBothWays(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	defer host.Close()
	member := mustJoin(t, s, host.Code)
	defer member.Close()

	ln := member.Listen()
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var echoErr error
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			echoErr = err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			echoErr = err
			return
		}
		_, echoErr = conn.Write(append([]byte("re:"), buf...))
	}()

	conn, err := host.Dial(member.PeerID, 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply) != "re:hello" {
		t.Errorf("got %q, want %q", reply, "re:hello")
	}

	wg.Wait()
	if echoErr != nil {
		t.Fatalf("echo side: %v", echoErr)
	}
}

// A ring's nodes load hundreds of megabytes before they are ready, so the
// dialer routinely arrives long before the acceptor. That is ordinary startup
// skew and must not be an error.
func TestDialerMayArriveFirst(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	defer host.Close()
	member := mustJoin(t, s, host.Code)
	defer member.Close()

	dialed := make(chan error, 1)
	go func() {
		conn, err := host.Dial(member.PeerID, 20*time.Second)
		if err != nil {
			dialed <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("late"))
		dialed <- err
	}()

	// The acceptor shows up well after the dialer has committed.
	time.Sleep(400 * time.Millisecond)
	ln := member.Listen()
	defer ln.Close()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "late" {
		t.Errorf("got %q, want %q", buf, "late")
	}
	if err := <-dialed; err != nil {
		t.Fatalf("dial side: %v", err)
	}
}

// The greeting is decoded with a json.Decoder, which reads ahead. Whatever it
// buffered past the reply is the peer's first bytes, and dropping them corrupts
// the stream in a way that shows up much later as a malformed frame rather than
// as a connection error.
//
// A large payload written immediately makes the read-ahead overlap likely, and
// checking the bytes rather than the length is what would catch a silent loss.
func TestNoBytesLostToTheGreetingsReadAhead(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	defer host.Close()
	member := mustJoin(t, s, host.Code)
	defer member.Close()

	payload := make([]byte, 256<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	ln := member.Listen()
	defer ln.Close()

	got := make(chan []byte, 1)
	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			errc <- err
			return
		}
		got <- buf
	}()

	conn, err := host.Dial(member.PeerID, 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Written with no pause, so the first bytes chase the greeting down the
	// same connection.
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case err := <-errc:
		t.Fatalf("accept side: %v", err)
	case b := <-got:
		if !bytes.Equal(b, payload) {
			t.Fatalf("payload differs: %d bytes in, %d out, first difference at %d",
				len(payload), len(b), firstDiff(payload, b))
		}
	case <-time.After(20 * time.Second):
		t.Fatal("payload never arrived")
	}
}

func firstDiff(a, b []byte) int {
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			return i
		}
	}
	return -1
}

func mustHost(t *testing.T, s *Server) *Session {
	t.Helper()
	h, err := Host(s.Addr(), "qwen", 2, "a")
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	return h
}

func mustJoin(t *testing.T, s *Server, code string) *Session {
	t.Helper()
	m, err := Join(s.Addr(), code, "b")
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	return m
}

// The path a real session takes: the host learns who joined and what they can
// carry, then reaches them through the transport the ring will use. Neither
// side ever accepts an unsolicited inbound connection.
func TestHostLearnsJoinsAndReachesThemThroughTheTransport(t *testing.T) {
	s := start(t)

	host, err := Host(s.Addr(), "qwen", 2, "host-machine")
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	defer host.Close()

	joined := make(chan []Event, 1)
	go func() {
		got, err := host.AwaitPeers(2, 10*time.Second)
		if err != nil {
			t.Errorf("await peers: %v", err)
		}
		joined <- got
	}()

	member, err := JoinWith(s.Addr(), host.Code, "friend-machine",
		[]byte(`{"working_set_bytes":8589934592,"gpu":true}`))
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	defer member.Close()

	var events []Event
	select {
	case events = <-joined:
	case <-time.After(10 * time.Second):
		t.Fatal("host never heard about the member")
	}
	if len(events) != 1 {
		t.Fatalf("host saw %d joins, want 1", len(events))
	}
	if events[0].PeerID != member.PeerID {
		t.Errorf("host was told peer %q, member has %q", events[0].PeerID, member.PeerID)
	}
	if !strings.Contains(string(events[0].Capability), "8589934592") {
		t.Errorf("capability did not reach the host intact: %s", events[0].Capability)
	}

	// Now the ring's own path, over the transports.
	hostT, memberT := host.Transport(), member.Transport()

	ln, err := memberT.Listen()
	if err != nil {
		t.Fatalf("member listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		_, err = io.ReadFull(conn, buf)
		if err == nil && string(buf) != "frame" {
			err = fmt.Errorf("got %q over the ring path", buf)
		}
		done <- err
	}()

	conn, err := hostT.Dial(member.PeerID, 10*time.Second)
	if err != nil {
		t.Fatalf("host dial member: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("frame")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("member side: %v", err)
	}
}
