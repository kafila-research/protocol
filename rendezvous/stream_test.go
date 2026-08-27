package rendezvous

import (
	"io"
	"net"
	"testing"
	"time"
)

// A peer keeps several listeners open at once, and a dial must reach the one it
// asked for.
//
// Before streams existed the rendezvous keyed parked accepts on the peer alone,
// so every listener a peer opened shared one queue and a dial was answered by
// whichever reached the front. A node serving ring frames on one listener and
// HTTP on another would hand the ring's frames to the HTTP server, and neither
// end would report anything: the connection forms, the bytes arrive, and the
// reader waits for a frame that will never be a frame.
func TestEachStreamReachesItsOwnListener(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	defer host.Close()
	member := mustJoin(t, s, host.Code)
	defer member.Close()

	// The ring's accepts park first, and only then the web's. Order matters:
	// keyed on the peer alone every accept sits in one queue, so the front of
	// it belongs to the ring — and the http dial below would be answered by a
	// ring listener. Opening them the other way round would let the wrong
	// behaviour pass by luck.
	ring := member.ListenStream("ring")
	defer ring.Close()
	time.Sleep(400 * time.Millisecond)
	web := member.ListenStream("http")
	defer web.Close()

	type got struct {
		where string
		body  string
		err   error
	}
	seen := make(chan got, 2)

	accept := func(name string, ln net.Listener) {
		conn, err := ln.Accept()
		if err != nil {
			seen <- got{where: name, err: err}
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			seen <- got{where: name, err: err}
			return
		}
		seen <- got{where: name, body: string(buf)}
	}
	go accept("ring", ring)
	go accept("http", web)

	// Both listeners must really be parked when the dials arrive: that is the
	// condition under which one shared queue handed a dial to the wrong one.
	time.Sleep(400 * time.Millisecond)

	// http first, against the queue order established above.
	sent := map[string]string{"http": "WEB!", "ring": "RING"}
	for _, stream := range []string{"http", "ring"} {
		conn, err := host.DialStream(member.PeerID, stream, 10*time.Second)
		if err != nil {
			t.Fatalf("dial %s: %v", stream, err)
		}
		if _, err := conn.Write([]byte(sent[stream])); err != nil {
			t.Fatalf("write %s: %v", stream, err)
		}
		conn.Close()
	}

	for range 2 {
		select {
		case g := <-seen:
			if g.err != nil {
				t.Fatalf("%s listener: %v", g.where, g.err)
			}
			if g.body != sent[g.where] {
				t.Fatalf("the %q listener received %q, which was sent to the other stream",
					g.where, g.body)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("a stream never reached its listener")
		}
	}
}
