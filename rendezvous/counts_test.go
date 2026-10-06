package rendezvous

import (
	"io"
	"net"
	"testing"
	"time"
)

// What the rendezvous relays is counted: datagrams and their bytes, datagrams
// it could not relay and why, and streams and their bytes, so a minute's
// report can say whether the relay is where a slow ring's time goes.
func TestTheRelayCountsWhatItCarries(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	member := mustJoin(t, s, host.Code)
	h, m := relayed(t, host), relayed(t, member)

	if _, err := h.WriteTo([]byte("hello"), h.AddrOf(member.PeerID)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readWithin(m, 2*time.Second); err != nil {
		t.Fatalf("the datagram did not arrive: %v", err)
	}

	// From a socket that never registered: not relayed, and counted as such.
	stranger, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	to, _ := net.ResolveUDPAddr("udp", s.Addr())
	frame := appendDatagramField([]byte{datagramFrameToPeer}, member.PeerID)
	if _, err := stranger.WriteTo(append(frame, "x"...), to); err != nil {
		t.Fatal(err)
	}

	// And a stream, one way.
	ln := member.Listen()
	got := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- -1
			return
		}
		defer c.Close()
		n, _ := io.Copy(io.Discard, c)
		got <- int(n)
	}()
	c, err := host.Dial(member.PeerID, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(make([]byte, 10000)); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if n := <-got; n != 10000 {
		t.Fatalf("the stream carried %d bytes, sent 10000", n)
	}

	c2 := &s.counts
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (c2.unknownSender.Load() == 0 || c2.streamBytes.Load() < 10000) {
		time.Sleep(20 * time.Millisecond)
	}
	if c2.datagrams.Load() < 1 || c2.datagramBytes.Load() < 5 {
		t.Errorf("relayed %d datagrams of %d bytes, want the one of 5", c2.datagrams.Load(), c2.datagramBytes.Load())
	}
	if c2.unknownSender.Load() != 1 {
		t.Errorf("%d datagrams from an unregistered sender, want 1", c2.unknownSender.Load())
	}
	if c2.streams.Load() != 1 || c2.streamBytes.Load() < 10000 {
		t.Errorf("%d streams carrying %d bytes, want 1 carrying at least 10000", c2.streams.Load(), c2.streamBytes.Load())
	}

	last := c2.report([8]int64{})
	if again := c2.report(last); again != last {
		t.Error("a minute with nothing relayed changed the totals")
	}
}
