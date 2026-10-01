package rendezvous

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kafila-research/protocol/direct"
	"github.com/kafila-research/protocol/reach"
)

// Every member is issued its own relay token at host and join, and the
// rendezvous can say which token belongs to whom.
func TestEveryMemberIsIssuedARelayToken(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	member := mustJoin(t, s, host.Code)
	if host.RelayToken == "" || member.RelayToken == "" || host.RelayToken == member.RelayToken {
		t.Fatalf("tokens %q and %q, want two distinct ones", host.RelayToken, member.RelayToken)
	}
	if tok, ok := s.memberToken(host.ID, member.PeerID); !ok || tok != member.RelayToken {
		t.Errorf("the member's token is %q, %v", tok, ok)
	}
	if _, ok := s.memberToken(host.ID, "nobody"); ok {
		t.Error("a peer that never joined has a token")
	}
}

// The relay shares the probe's port, and probes are still answered on it.
func TestProbesAreStillAnsweredBesideTheRelay(t *testing.T) {
	s := start(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := reach.ProbeVia(pc, s.Addr(), 2*time.Second); err != nil {
		t.Fatalf("probe beside the relay: %v", err)
	}
}

// relayed opens a member's datagram relay, failing the test where it cannot.
func relayed(t *testing.T, sess *Session) *DatagramConn {
	t.Helper()
	c, err := sess.Datagrams(2 * time.Second)
	if err != nil {
		t.Fatalf("datagrams for %s: %v", sess.PeerID, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// readWithin reads one packet, or reports that none came.
func readWithin(c *DatagramConn, d time.Duration) ([]byte, net.Addr, error) {
	_ = c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 65536)
	n, from, err := c.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}
	return buf[:n], from, nil
}

func registerDatagramReceiver(t *testing.T, sess *Session, pc net.PacketConn) {
	t.Helper()

	relay, err := net.ResolveUDPAddr("udp", sess.Addr)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte{datagramFrameRegister}
	frame = appendDatagramField(frame, sess.ID)
	frame = appendDatagramField(frame, sess.PeerID)
	frame = appendDatagramField(frame, sess.RelayToken)
	if _, err := pc.WriteTo(frame, relay); err != nil {
		t.Fatal(err)
	}

	var ack [16]byte
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer pc.SetReadDeadline(time.Time{})
	n, _, err := pc.ReadFrom(ack[:])
	if err != nil {
		t.Fatalf("registration ack: %v", err)
	}
	if n == 0 || ack[0] != datagramFrameAck {
		t.Fatalf("registration ack frame %v", ack[:n])
	}
}

// A packet reaches the member it names, both ways, and arrives from the
// stand-in address of the member that sent it.
func TestDatagramsReachTheMemberNamed(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	member := mustJoin(t, s, host.Code)
	h, m := relayed(t, host), relayed(t, member)

	if _, err := h.WriteTo([]byte("to the member"), h.AddrOf(member.PeerID)); err != nil {
		t.Fatal(err)
	}
	got, from, err := readWithin(m, 2*time.Second)
	if err != nil || string(got) != "to the member" || from.String() != m.AddrOf(host.PeerID).String() {
		t.Fatalf("member read %q from %v (%v), want it from the host at %v", got, from, err, m.AddrOf(host.PeerID))
	}

	if _, err := m.WriteTo([]byte("and back"), m.AddrOf(host.PeerID)); err != nil {
		t.Fatal(err)
	}
	got, from, err = readWithin(h, 2*time.Second)
	if err != nil || string(got) != "and back" || from.String() != h.AddrOf(member.PeerID).String() {
		t.Fatalf("host read %q from %v (%v)", got, from, err)
	}
}

// A receiver that stops registering expires after the TTL, even while others
// keep sending to it, because only packets from that receiver refresh it.
func TestIdleReceiverExpiresUnderInboundTraffic(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	member := mustJoin(t, s, host.Code)
	sender := relayed(t, host)

	receiverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiverPC.Close()
	registerDatagramReceiver(t, member, receiverPC)

	if _, err := sender.WriteTo([]byte("before-expiry"), sender.AddrOf(member.PeerID)); err != nil {
		t.Fatal(err)
	}
	var buf [2048]byte
	_ = receiverPC.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := receiverPC.ReadFrom(buf[:])
	if err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	_, payload, ok := parseRelayedDatagram(buf[:n])
	if !ok || string(payload) != "before-expiry" {
		t.Fatalf("before expiry got %q", payload)
	}

	keepSendingUntil := time.Now().Add(datagramRegistrationTTL + 2*datagramRegistrationSweepInterval)
	for time.Now().Before(keepSendingUntil) {
		if _, err := sender.WriteTo([]byte("keep-sending"), sender.AddrOf(member.PeerID)); err != nil {
			t.Fatal(err)
		}
		_ = receiverPC.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
		if n, _, err := receiverPC.ReadFrom(buf[:]); err == nil {
			_, _, _ = parseRelayedDatagram(buf[:n])
		}
	}

	for i := 0; i < 3; i++ {
		if _, err := sender.WriteTo([]byte("after-expiry"), sender.AddrOf(member.PeerID)); err != nil {
			t.Fatal(err)
		}
		_ = receiverPC.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, err := receiverPC.ReadFrom(buf[:])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			t.Fatalf("after expiry read: %v", err)
		}
		if _, payload, ok := parseRelayedDatagram(buf[:n]); ok {
			t.Fatalf("received %q after expiry", payload)
		}
	}
}

// Stand-in addresses are UDP addresses in a range never routed, the same for
// a peer each time and different between peers.
func TestStandInAddressesAreStableAndDistinct(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	h := relayed(t, host)
	a, again, b := h.AddrOf("peer-a"), h.AddrOf("peer-a"), h.AddrOf("peer-b")
	if a.String() != again.String() || a.String() == b.String() {
		t.Fatalf("stand-ins %v, %v, %v", a, again, b)
	}
	_, unrouted, _ := net.ParseCIDR("198.18.0.0/15")
	for _, addr := range []net.Addr{a, b} {
		u, ok := addr.(*net.UDPAddr)
		if !ok || !unrouted.Contains(u.IP) {
			t.Errorf("stand-in %v (%T) is not a UDP address in 198.18.0.0/15", addr, addr)
		}
	}
}

// Registering needs the member's own token: another member's, or none, is
// refused, and refused as ErrNoDatagrams so the caller relays over TCP.
func TestARegistrationNeedsTheMembersOwnToken(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	member := mustJoin(t, s, host.Code)

	for _, token := range []string{host.RelayToken, "", "not-a-token"} {
		impostor := *member
		impostor.control = nil
		impostor.RelayToken = token
		if c, err := impostor.Datagrams(500 * time.Millisecond); !errors.Is(err, ErrNoDatagrams) {
			if c != nil {
				c.Close()
			}
			t.Errorf("registering as the member with token %q: %v, want ErrNoDatagrams", token, err)
		}
	}
}

// A member of one session cannot reach a member of another, even naming it.
func TestDatagramsStayInTheirSession(t *testing.T) {
	s := start(t)
	first := mustHost(t, s)
	firstMember := mustJoin(t, s, first.Code)
	second := mustHost(t, s)
	f, other := relayed(t, firstMember), relayed(t, second)
	_ = relayed(t, first)

	if _, err := other.WriteTo([]byte("across sessions"), other.AddrOf(firstMember.PeerID)); err != nil {
		t.Fatal(err)
	}
	if got, from, err := readWithin(f, 500*time.Millisecond); err == nil {
		t.Fatalf("a member of another session delivered %q from %v", got, from)
	}
}

// Without a relay to answer, Datagrams gives up at its timeout with
// ErrNoDatagrams, so a ring is not held up by a rendezvous too old to relay.
func TestNoRelayIsNoDatagramsPromptly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sess := &Session{Addr: ln.Addr().String(), ID: "session", PeerID: "peer", RelayToken: "token"}
	began := time.Now()
	c, err := sess.Datagrams(300 * time.Millisecond)
	if !errors.Is(err, ErrNoDatagrams) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("with nothing relaying: %v, want ErrNoDatagrams", err)
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Errorf("took %v to give up on a 300ms timeout", took)
	}
	if _, err := (&Session{Addr: ln.Addr().String(), ID: "session", PeerID: "peer"}).Datagrams(time.Second); !errors.Is(err, ErrNoDatagrams) {
		t.Errorf("with no token issued: %v, want ErrNoDatagrams", err)
	}
}

// QUIC runs over relayed datagrams as it does over a socket: the same pinned
// keys, a stream each way, and a frame far larger than one packet arriving
// whole. This is what Kafila's rings do with it.
func TestQUICRunsOverRelayedDatagrams(t *testing.T) {
	s := start(t)
	host := mustHost(t, s)
	member := mustJoin(t, s, host.Code)
	h, m := relayed(t, host), relayed(t, member)

	hid, err := direct.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	mid, err := direct.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	he, err := direct.New(h, hid, map[string]direct.Peer{member.PeerID: {Addr: h.AddrOf(member.PeerID).String(), Fingerprint: mid.Fingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	defer he.Close()
	me, err := direct.New(m, mid, map[string]direct.Peer{host.PeerID: {Addr: m.AddrOf(host.PeerID).String(), Fingerprint: hid.Fingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	defer me.Close()

	ln, err := me.Listen()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 200<<10)
	_, _ = rand.Read(frame)
	echoed := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			echoed <- err
			return
		}
		defer c.Close()
		got := make([]byte, len(frame))
		if _, err := io.ReadFull(c, got); err != nil {
			echoed <- err
			return
		}
		_, err = c.Write(got)
		echoed <- err
	}()

	c, err := he.Dial(member.PeerID, 5*time.Second)
	if err != nil {
		t.Fatalf("dial over the relay: %v", err)
	}
	defer c.Close()
	if _, err := c.Write(frame); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(frame))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, back); err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	if err := <-echoed; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, frame) {
		t.Fatal("the frame came back different")
	}
}
