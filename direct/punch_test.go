package direct

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// Two ends traverse to each other and then carry real traffic over what they
// found.
//
// Loopback has no NAT, so this does not prove traversal defeats one — nothing
// on one machine can. What it does prove is the part that is ours rather than
// the network's: that the candidate exchange completes without either side
// waiting on the other, that punch packets are recognised on a socket QUIC is
// also using, that the address learned is one that works, and that a connection
// then stands up over it. Whether a NAT yields is a question only two real
// networks can answer, and the field measurement is C4's.
func TestTraversalFindsAPathAndCarriesTraffic(t *testing.T) {
	a, aid := endpoint(t)
	b, bid := endpoint(t)

	// Stands in for the relayed stream the two peers already have between them.
	coordA, coordB := net.Pipe()
	defer coordA.Close()
	defer coordB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	type found struct {
		peer Peer
		err  error
	}
	fa := make(chan found, 1)
	fb := make(chan found, 1)

	go func() {
		p, err := Traverse(ctx, coordA, a,
			Candidate{Local: a.LocalAddr().String(), Fingerprint: aid.Fingerprint}, 10*time.Second)
		fa <- found{p, err}
	}()
	go func() {
		p, err := Traverse(ctx, coordB, b,
			Candidate{Local: b.LocalAddr().String(), Fingerprint: bid.Fingerprint}, 10*time.Second)
		fb <- found{p, err}
	}()

	var pa, pb Peer
	for range 2 {
		select {
		case r := <-fa:
			if r.err != nil {
				t.Fatalf("a traversing to b: %v", r.err)
			}
			pa = r.peer
		case r := <-fb:
			if r.err != nil {
				t.Fatalf("b traversing to a: %v", r.err)
			}
			pb = r.peer
		case <-time.After(25 * time.Second):
			t.Fatal("traversal never completed")
		}
	}

	if pa.Fingerprint != bid.Fingerprint {
		t.Fatalf("a learned key %q, want b's %q", pa.Fingerprint, bid.Fingerprint)
	}
	if pb.Fingerprint != aid.Fingerprint {
		t.Fatalf("b learned key %q, want a's %q", pb.Fingerprint, aid.Fingerprint)
	}

	// The address each side learned must be the one the other is actually on.
	// This is the check that would catch a punch reporting its own socket, or
	// the source of some unrelated packet.
	if pa.Addr != b.LocalAddr().String() {
		t.Fatalf("a learned %s for b, which is on %s", pa.Addr, b.LocalAddr())
	}
	if pb.Addr != a.LocalAddr().String() {
		t.Fatalf("b learned %s for a, which is on %s", pb.Addr, a.LocalAddr())
	}

	// And the path works: a ring edge runs one way, so a dials and b accepts.
	a.Learn("b", pa)
	b.Learn("a", pb)

	bln, err := b.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	got := make(chan []byte, 1)
	go func() {
		conn, err := bln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			got <- nil
			return
		}
		got <- buf
	}()

	conn, err := a.Dial("b", 10*time.Second)
	if err != nil {
		t.Fatalf("dial over the punched path: %v", err)
	}
	if _, err := conn.Write([]byte("frame")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	select {
	case g := <-got:
		if !bytes.Equal(g, []byte("frame")) {
			t.Fatalf("b received %q over the punched path", g)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("nothing crossed the punched path")
	}
}

// An edge with nowhere to aim reports that it has no path, rather than hanging
// or failing in a way a caller would treat as fatal.
//
// Falling back to a relay is a normal outcome — the protocol's §10 ranks it
// second, not last — so it has to be distinguishable from a broken edge.
func TestNoReachableCandidateMeansNoPathRatherThanAnError(t *testing.T) {
	a, aid := endpoint(t)

	coordA, coordB := net.Pipe()
	defer coordA.Close()
	defer coordB.Close()

	// The far end offers an address nothing answers on. It is written straight
	// onto the stream rather than by running Traverse on a second endpoint,
	// because a second endpoint would answer the punch and there would be a
	// path — which is what the first version of this test accidentally measured.
	go func() {
		_ = json.NewEncoder(coordB).Encode(Candidate{
			Local:       "127.0.0.1:1",
			Fingerprint: "a-key-nothing-holds",
		})
		_, _ = io.Copy(io.Discard, coordB) // absorb our candidate
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := Traverse(ctx, coordA, a,
		Candidate{Local: a.LocalAddr().String(), Fingerprint: aid.Fingerprint}, 2*time.Second)
	if err == nil {
		t.Fatal("traversal claimed a path to an address nothing answers on")
	}
	if !errors.Is(err, ErrNoPath) {
		t.Fatalf("error was %v, which a caller cannot tell apart from a broken edge; want ErrNoPath", err)
	}
}

// A node in a ring of more than two traverses to both its neighbours at once,
// on one socket, because the mapping a punch opens belongs to that socket and
// no other. Both attempts therefore see every punch packet that arrives.
//
// Each must come back with its own peer's address. Getting the other's is worse
// than failing: the address is learned, the edge is reported direct, and the
// mistake only surfaces later when the far end answers with the wrong key and
// the connection is dropped -- so the edge is relayed for a reason that has
// nothing to do with whether a direct path existed.
func TestConcurrentTraversalsDoNotTakeEachOthersPeers(t *testing.T) {
	middle, mid := endpoint(t)
	left, lid := endpoint(t)
	right, rid := endpoint(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Two coordination streams, as a ring node has: one to each neighbour.
	toLeftA, toLeftB := net.Pipe()
	toRightA, toRightB := net.Pipe()
	defer toLeftA.Close()
	defer toLeftB.Close()
	defer toRightA.Close()
	defer toRightB.Close()

	cand := func(e *Endpoint, id *Identity) Candidate {
		return Candidate{Local: e.LocalAddr().String(), Fingerprint: id.Fingerprint}
	}

	type result struct {
		peer Peer
		err  error
	}
	gotLeft := make(chan result, 1)
	gotRight := make(chan result, 1)

	// The middle node, traversing to both neighbours on one endpoint.
	go func() {
		p, err := Traverse(ctx, toLeftA, middle, cand(middle, mid), 10*time.Second)
		gotLeft <- result{p, err}
	}()
	go func() {
		p, err := Traverse(ctx, toRightA, middle, cand(middle, mid), 10*time.Second)
		gotRight <- result{p, err}
	}()
	// The neighbours, each traversing to the middle.
	go func() { _, _ = Traverse(ctx, toLeftB, left, cand(left, lid), 10*time.Second) }()
	go func() { _, _ = Traverse(ctx, toRightB, right, cand(right, rid), 10*time.Second) }()

	var l, r result
	select {
	case l = <-gotLeft:
	case <-time.After(30 * time.Second):
		t.Fatal("the traversal to the left neighbour never finished")
	}
	select {
	case r = <-gotRight:
	case <-time.After(30 * time.Second):
		t.Fatal("the traversal to the right neighbour never finished")
	}
	if l.err != nil {
		t.Fatalf("traversing to the left neighbour: %v", l.err)
	}
	if r.err != nil {
		t.Fatalf("traversing to the right neighbour: %v", r.err)
	}

	// The address each attempt found must be the socket of the peer it was
	// arranging with -- the fingerprint says which peer that is.
	for _, c := range []struct {
		side string
		got  Peer
		want *Endpoint
	}{
		{"left", l.peer, left},
		{"right", r.peer, right},
	} {
		if c.got.Addr != c.want.LocalAddr().String() {
			t.Errorf("the %s edge learned %s; that neighbour is at %s",
				c.side, c.got.Addr, c.want.LocalAddr())
		}
	}
	if l.peer.Addr == r.peer.Addr {
		t.Errorf("both edges learned the same address %s, so at least one is the wrong peer", l.peer.Addr)
	}
}
