package rendezvous

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

// A greeting whose trailing newline arrives after the JSON must not put that
// newline into the peer's stream.
//
// json.Encoder.Encode writes the value and a newline, and json.Decoder stops at
// the end of the value without consuming it. Usually both land in the decoder's
// buffer and are discarded together. Split across two segments — which is
// entirely up to TCP, and happened across a VPN — the newline stays in the
// socket and gets relayed to the peer in front of its first frame. The frame
// header is then read one byte off, yielding a length nobody sent, and the
// reader waits for bytes that are never coming. Neither end sees an error.
//
// The dial side is written by hand here because the real client cannot produce
// the segmentation: Encode emits the value and the newline in one write.
func TestGreetingNewlineIsNotRelayedToThePeer(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	defer host.Close()
	member := mustJoin(t, s, host.Code)
	defer member.Close()

	ln := member.Listen()
	defer ln.Close()

	payload := bytes.Repeat([]byte("kafila"), 4096) // larger than one segment
	got := make(chan []byte, 1)
	fail := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			fail <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			fail <- err
			return
		}
		got <- buf
	}()

	raw, err := net.DialTimeout("tcp", host.Addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial rendezvous: %v", err)
	}
	defer raw.Close()

	// The greeting, and then its newline as a separate segment.
	body, err := json.Marshal(Hello{
		Op: "dial", Session: host.ID, From: host.PeerID, To: member.PeerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(body); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := raw.Write([]byte("\n")); err != nil {
		t.Fatalf("write newline: %v", err)
	}

	var w Welcome
	dec := json.NewDecoder(raw)
	if err := dec.Decode(&w); err != nil {
		t.Fatalf("no welcome: %v", err)
	}
	if !w.OK {
		t.Fatalf("welcome refused: %s", w.Error)
	}
	// Eat the newline after the welcome, as the real client does.
	rest := io.MultiReader(dec.Buffered(), raw)
	var nl [1]byte
	if _, err := io.ReadFull(rest, nl[:]); err != nil || nl[0] != '\n' {
		t.Fatalf("welcome not newline-terminated: %q %v", nl[0], err)
	}

	if _, err := raw.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	select {
	case b := <-got:
		if !bytes.Equal(b, payload) {
			for i := range b {
				if b[i] != payload[i] {
					t.Fatalf("the peer's stream was corrupted at byte %d: got %q, want %q",
						i, b[i], payload[i])
				}
			}
		}
	case err := <-fail:
		t.Fatalf("peer did not receive the payload: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the payload never arrived; the peer is blocked on a frame length nobody sent")
	}
}
