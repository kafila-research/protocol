package rendezvous

import (
	"errors"
	"os"
	"testing"
	"time"
)

// The timeout has to bound the reply, not just the connection.
//
// Reaching the rendezvous is the quick part; a dial is then parked until the
// peer it names accepts. For a peer that never accepts — one that crashed after
// joining, or that is not attempting this at all — the welcome never comes, and
// bounding only the TCP connect left the caller waiting on that forever while
// holding a timeout it had every reason to think applied.
//
// Found from the other side: a session stalled before wiring its ring because
// the far end never opened the stream this dials.
func TestDialStreamGivesUpOnAPeerThatNeverAccepts(t *testing.T) {
	srv := NewServer()
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	host, err := HostWith(srv.Addr(), "model", 2, "host", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	// A member that joins and then listens for nothing.
	silent, err := JoinWith(srv.Addr(), host.Code, "silent", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	started := time.Now()
	conn, err := host.DialStream(silent.PeerID, "punch", 750*time.Millisecond)
	took := time.Since(started)

	if err == nil {
		conn.Close()
		t.Fatal("dialled a peer that never accepted")
	}
	if took > 5*time.Second {
		t.Fatalf("gave up after %s, having been given 750ms: the timeout does not bound the reply", took)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Logf("gave up in %s with: %v", took, err)
	}
}

// And a connection that is handed over must not carry the deadline that bounded
// its greeting, or it stops working under whoever reads it next.
func TestAPairedStreamDoesNotInheritTheGreetingDeadline(t *testing.T) {
	srv := NewServer()
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	host, err := HostWith(srv.Addr(), "model", 2, "host", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	member, err := JoinWith(srv.Addr(), host.Code, "member", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer member.Close()

	accepted := make(chan error, 1)
	go func() {
		ln := member.ListenStream("ring")
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer c.Close()
		// Well after any greeting deadline would have expired.
		time.Sleep(1200 * time.Millisecond)
		_, err = c.Write([]byte("late\n"))
		accepted <- err
	}()

	conn, err := host.DialStream(member.PeerID, "ring", time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := <-accepted; err != nil {
		t.Fatalf("the far end could not write after the greeting deadline would have passed: %v", err)
	}

	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("reading a paired stream failed after the greeting deadline: %v", err)
	}
}
