package rendezvous

import (
	"io"
	"testing"
	"time"
)

// The exact sequence a session performs, without a model in the way.
//
// A member opens a listener to receive its assignment, closes it, and opens a
// second one for the ring. Meanwhile the host dials the member twice: once to
// deliver the plan and once to wire the ring. The second dial must reach the
// second listener.
//
// This is written because the failure it reproduces cost several minutes per
// attempt to observe through model loads: the ring formed, both shards loaded,
// and then the head waited forever for a frame that never came back.
func TestSecondDialReachesTheSecondListener(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	defer host.Close()
	member := mustJoin(t, s, host.Code)
	defer member.Close()

	// --- the member takes its assignment on a listener it then discards ---
	first := member.Listen()
	firstGot := make(chan error, 1)
	go func() {
		conn, err := first.Accept()
		if err != nil {
			firstGot <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		_, err = io.ReadFull(conn, buf)
		firstGot <- err
	}()

	deliver, err := host.Dial(member.PeerID, 10*time.Second)
	if err != nil {
		t.Fatalf("deliver dial: %v", err)
	}
	if _, err := deliver.Write([]byte("plan!")); err != nil {
		t.Fatalf("deliver write: %v", err)
	}
	if err := <-firstGot; err != nil {
		t.Fatalf("member did not receive its assignment: %v", err)
	}
	deliver.Close()
	first.Close()

	// --- and then serves the ring on a fresh one ---
	second := member.Listen()
	defer second.Close()

	ringGot := make(chan error, 1)
	go func() {
		conn, err := second.Accept()
		if err != nil {
			ringGot <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		_, err = io.ReadFull(conn, buf)
		ringGot <- err
	}()

	ring, err := host.Dial(member.PeerID, 10*time.Second)
	if err != nil {
		t.Fatalf("ring dial: %v", err)
	}
	defer ring.Close()
	if _, err := ring.Write([]byte("frame")); err != nil {
		t.Fatalf("ring write: %v", err)
	}

	select {
	case err := <-ringGot:
		if err != nil {
			t.Fatalf("ring frame did not arrive intact: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the ring frame never reached the second listener — it was spliced to an accept left over from the closed one")
	}
}

// Both directions at once, which is what a ring actually does: each node dials
// its successor while accepting from its predecessor.
func TestTwoPeersDialEachOtherSimultaneously(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	defer host.Close()
	member := mustJoin(t, s, host.Code)
	defer member.Close()

	hostLn, memberLn := host.Listen(), member.Listen()
	defer hostLn.Close()
	defer memberLn.Close()

	type result struct {
		who string
		err error
	}
	done := make(chan result, 2)

	go func() {
		conn, err := memberLn.Accept()
		if err == nil {
			buf := make([]byte, 4)
			_, err = io.ReadFull(conn, buf)
			conn.Close()
		}
		done <- result{"member-accept", err}
	}()
	go func() {
		conn, err := hostLn.Accept()
		if err == nil {
			buf := make([]byte, 4)
			_, err = io.ReadFull(conn, buf)
			conn.Close()
		}
		done <- result{"host-accept", err}
	}()

	// Both dial before either has been accepted, which is the ordering a ring
	// startup produces and the one that deadlocks without a backlog.
	go func() {
		c, err := host.Dial(member.PeerID, 15*time.Second)
		if err == nil {
			_, err = c.Write([]byte("h->m"))
		}
		if err != nil {
			done <- result{"host-dial", err}
		}
	}()
	go func() {
		c, err := member.Dial(host.PeerID, 15*time.Second)
		if err == nil {
			_, err = c.Write([]byte("m->h"))
		}
		if err != nil {
			done <- result{"member-dial", err}
		}
	}()

	for range 2 {
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatalf("%s: %v", r.who, r.err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("the ring did not close: both peers dialled and neither was spliced")
		}
	}
}
