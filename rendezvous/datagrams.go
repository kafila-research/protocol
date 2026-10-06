package rendezvous

import (
	"crypto/hmac"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Relayed datagrams: the server side.
//
// # Why it exists
//
// Ring frames relayed over TCP wait an extra round trip on every relayed leg
// once they are larger than the connection's restarted congestion window, and
// a ring link idles between tokens, so the window restarts every frame. Kafila
// measured a 20 KB frame at 342 ms against 223 ms for one byte through the
// relay, and the same frames as QUIC packets at 229 ms. Relaying the members'
// QUIC packets removes that cost without changing any machine's settings. The
// packets are the members' own QUIC traffic, authenticated end to end by the
// keys they exchanged through the host; the relay neither reads nor alters
// what they carry.
//
// The relay shares the probe's primary UDP socket, so every relay packet starts
// with a non-JSON opcode byte and never with '{'. Frames then carry
// length-prefixed fields (one-byte length, then bytes):
//
//   - register: 1, session, peer, relay-token.
//   - ack: 2.
//   - to-peer: 3, destination-peer, payload.
//   - from-peer: 4, source-peer, payload.
//
// Registrations are keyed by member and by source address, expire after
// datagramRegistrationTTL of inactivity, and can be replaced when a member
// registers again from a new address. Only packets that arrive from a member
// refresh its liveness. Expiry sweeps run at most once each
// datagramRegistrationSweepInterval so every packet does not pay an O(n) scan.
//
// handle runs on the socket's reading goroutine, so it only parses and updates
// tables inline, then enqueues any write without blocking. Packet contents that
// come from the shared read buffer are copied before they can outlive the call.

const (
	datagramFrameRegister byte = 1
	datagramFrameAck      byte = 2
	datagramFrameToPeer   byte = 3
	datagramFrameFromPeer byte = 4

	datagramRegistrationTTL           = 12 * time.Second
	datagramRegistrationSweepInterval = time.Second
)

type relayRegistration struct {
	session string
	peer    string
	addr    net.Addr
	seen    time.Time
}

type relayWrite struct {
	pc   net.PacketConn
	to   net.Addr
	data []byte
}

// datagramRelay is the rendezvous's datagram relay.
type datagramRelay struct {
	// token reports the relay token issued to a peer in a session, and
	// whether that peer is a member of it (Server.memberToken).
	token func(session, peer string) (string, bool)

	mu        sync.Mutex
	byMember  map[string]*relayRegistration
	byAddr    map[string]*relayRegistration
	lastSweep time.Time
	writes    chan relayWrite

	// counts is the server's, or a set of its own for a relay made alone.
	counts *relayCounts
}

// newDatagramRelay is a relay that checks registrations with token.
func newDatagramRelay(token func(session, peer string) (string, bool)) *datagramRelay {
	r := &datagramRelay{
		token:    token,
		byMember: map[string]*relayRegistration{},
		byAddr:   map[string]*relayRegistration{},
		writes:   make(chan relayWrite, 256),
		counts:   &relayCounts{},
	}
	go r.writeLoop()
	return r
}

func (r *datagramRelay) writeLoop() {
	for w := range r.writes {
		if _, err := w.pc.WriteTo(w.data, w.to); err != nil {
			r.counts.writeFailed.Add(1)
			slog.Debug("rendezvous datagram write failed", "to", w.to, "error", err)
		}
	}
}

func (r *datagramRelay) enqueueWrite(pc net.PacketConn, to net.Addr, data []byte) {
	select {
	case r.writes <- relayWrite{pc: pc, to: cloneAddr(to), data: data}:
	default:
		r.counts.queueFull.Add(1)
		slog.Debug("rendezvous datagram write queue full", "to", to)
	}
}

func relayMemberKey(session, peer string) string { return session + "\x00" + peer }

func (r *datagramRelay) expire(now time.Time) {
	for memberKey, reg := range r.byMember {
		if now.Sub(reg.seen) <= datagramRegistrationTTL {
			continue
		}
		delete(r.byMember, memberKey)
		if current := r.byAddr[reg.addr.String()]; current == reg {
			delete(r.byAddr, reg.addr.String())
		}
	}
}

func (r *datagramRelay) expireIfDue(now time.Time) {
	if now.Sub(r.lastSweep) < datagramRegistrationSweepInterval {
		return
	}
	r.expire(now)
	r.lastSweep = now
}

func parseDatagramField(frame []byte, at *int) (string, bool) {
	if *at >= len(frame) {
		return "", false
	}
	n := int(frame[*at])
	*at++
	if n > len(frame)-*at {
		return "", false
	}
	s := string(frame[*at : *at+n])
	*at += n
	return s, true
}

func appendDatagramField(dst []byte, s string) []byte {
	if len(s) > 255 {
		s = s[:255]
	}
	dst = append(dst, byte(len(s)))
	return append(dst, s...)
}

func cloneAddr(addr net.Addr) net.Addr {
	u, ok := addr.(*net.UDPAddr)
	if !ok {
		return addr
	}
	cpy := &net.UDPAddr{Port: u.Port, Zone: u.Zone}
	if u.IP != nil {
		cpy.IP = append(net.IP(nil), u.IP...)
	}
	return cpy
}

// handle takes one packet that arrived on the probe's primary port from from,
// and is not a probe. It runs on the port's reading goroutine; b is reused
// after it returns.
func (r *datagramRelay) handle(pc net.PacketConn, b []byte, from net.Addr) {
	if len(b) == 0 {
		return
	}
	now := time.Now()

	switch b[0] {
	case datagramFrameRegister:
		at := 1
		session, ok := parseDatagramField(b, &at)
		if !ok {
			return
		}
		peer, ok := parseDatagramField(b, &at)
		if !ok {
			return
		}
		token, ok := parseDatagramField(b, &at)
		if !ok || at != len(b) {
			return
		}

		want, member := r.token(session, peer)
		if !member || !hmac.Equal([]byte(token), []byte(want)) {
			return
		}

		reg := &relayRegistration{session: session, peer: peer, addr: cloneAddr(from), seen: now}
		memberKey := relayMemberKey(session, peer)
		addrKey := from.String()

		r.mu.Lock()
		r.expireIfDue(now)
		if old, ok := r.byMember[memberKey]; ok {
			delete(r.byAddr, old.addr.String())
		}
		if old, ok := r.byAddr[addrKey]; ok {
			delete(r.byMember, relayMemberKey(old.session, old.peer))
		}
		r.byMember[memberKey] = reg
		r.byAddr[addrKey] = reg
		r.mu.Unlock()

		r.enqueueWrite(pc, from, []byte{datagramFrameAck})

	case datagramFrameToPeer:
		at := 1
		toPeer, ok := parseDatagramField(b, &at)
		if !ok {
			return
		}
		payload := b[at:]

		r.mu.Lock()
		r.expireIfDue(now)
		sender := r.byAddr[from.String()]
		if sender == nil {
			r.mu.Unlock()
			r.counts.unknownSender.Add(1)
			return
		}
		sender.seen = now
		receiver := r.byMember[relayMemberKey(sender.session, toPeer)]
		r.mu.Unlock()
		if receiver == nil {
			r.counts.unknownReceiver.Add(1)
			return
		}
		r.counts.datagrams.Add(1)
		r.counts.datagramBytes.Add(int64(len(payload)))

		frame := []byte{datagramFrameFromPeer}
		frame = appendDatagramField(frame, sender.peer)
		frame = append(frame, payload...)
		r.enqueueWrite(pc, receiver.addr, frame)
	}
}
