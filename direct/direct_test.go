package direct

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// endpoint builds one node's data plane on a loopback socket.
func endpoint(t *testing.T) (*Endpoint, *Identity) {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	e, err := New(pc, id, nil)
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e, id
}

// introduce tells a about b, the way the rendezvous will.
func introduce(a *Endpoint, name string, b *Endpoint, bid *Identity) {
	a.Learn(name, Peer{Addr: b.LocalAddr().String(), Fingerprint: bid.Fingerprint})
}

// A stream opened over a direct path carries bytes, in both directions, and
// looks like a net.Conn to whatever is holding it.
//
// Both directions matter rather than being symmetry for its own sake: a ring
// link is one-way, but the two nodes at each end of an edge both dial and both
// accept, on the same socket. That is what a hole punch leaves behind.
func TestAStreamCarriesBytesEachWay(t *testing.T) {
	a, aid := endpoint(t)
	b, bid := endpoint(t)
	introduce(a, "b", b, bid)
	introduce(b, "a", a, aid)

	bln, err := b.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	aln, err := a.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	echo := func(ln net.Listener, out chan<- []byte) {
		conn, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			out <- nil
			return
		}
		out <- buf
	}

	atob := make(chan []byte, 1)
	go echo(bln, atob)

	conn, err := a.Dial("b", 10*time.Second)
	if err != nil {
		t.Fatalf("a dials b: %v", err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	select {
	case got := <-atob:
		if !bytes.Equal(got, []byte("hello")) {
			t.Fatalf("b received %q", got)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("nothing reached b")
	}

	// And back the other way, on the same sockets.
	btoa := make(chan []byte, 1)
	go echo(aln, btoa)

	conn2, err := b.Dial("a", 10*time.Second)
	if err != nil {
		t.Fatalf("b dials a: %v", err)
	}
	if _, err := conn2.Write([]byte("world")); err != nil {
		t.Fatalf("write back: %v", err)
	}
	conn2.Close()

	select {
	case got := <-btoa:
		if !bytes.Equal(got, []byte("world")) {
			t.Fatalf("a received %q", got)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("nothing reached a")
	}
}

// A direct path must not be easier to speak into than the relayed one it
// replaces.
//
// The relay gates an edge behind the rendezvous: a peer needs the session id and
// the peer id to be paired with anybody. A UDP socket on the open internet has
// no such gate, so the fingerprint is the whole of the access control, and a key
// this session never published has to be refused at the handshake.
func TestAKeyTheSessionNeverPublishedIsRefused(t *testing.T) {
	a, _ := endpoint(t)
	b, bid := endpoint(t)

	// a knows b. b has been told about nobody, so a's key is unknown to it.
	introduce(a, "b", b, bid)

	if _, err := b.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	if _, err := a.Dial("b", 6*time.Second); err == nil {
		t.Fatal("b accepted a key it was never told about")
	}
}

// Dialling a peer that answers with the wrong key must fail, not merely warn.
//
// Aiming at an address is not the same as reaching a member: addresses are
// reused, NATs remap, and a punch can land on whatever now owns that port.
func TestAnImpostorAtTheRightAddressIsRefused(t *testing.T) {
	a, aid := endpoint(t)
	b, bid := endpoint(t)

	// A third key that is not b's.
	other, err := NewIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	// a is told b's address but somebody else's fingerprint.
	a.Learn("b", Peer{Addr: b.LocalAddr().String(), Fingerprint: other.Fingerprint})
	introduce(b, "a", a, aid)

	if _, err := b.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, err = a.Dial("b", 6*time.Second)
	if err == nil {
		t.Fatal("a accepted a peer presenting the wrong key")
	}
	if bid.Fingerprint == other.Fingerprint {
		t.Fatal("the test generated the same key twice, which makes it prove nothing")
	}
}
