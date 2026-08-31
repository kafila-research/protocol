package direct

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// Hole punching, and the candidate exchange that precedes it.
//
// The mechanism is the ordinary one: both ends send to the other's external
// address at the same time, each outbound packet opens a mapping in its own NAT,
// and whichever arrives after the far mapping exists gets through. What matters
// here is what surrounds it — where the addresses come from, how the two ends
// agree on a moment, and what is learned when the prediction is wrong.

// punchMagic marks a traversal packet.
//
// It is deliberately not a QUIC packet. quic-go hands anything it does not
// recognise to ReadNonQUICPacket, so the punch and the connection that follows
// share a socket without either having to parse the other's traffic. The first
// byte avoids the QUIC long-header bit pattern so nothing downstream has to
// guess.
var punchMagic = [4]byte{0x2a, 0x4b, 0x46, 0x50} // *KFP

// A punch carries the magic and then the sender's key fingerprint:
//
//	*KFP | sha256(sender public key)      4 + 32 bytes
//
// The fingerprint is there to say which peer sent the packet, because one
// socket may be punching to several at once. A node in a ring of more than two
// arranges both its edges at the same time, and it must: the mapping a punch
// opens belongs to the socket, so both attempts have to use the one socket, and
// therefore both see every packet that arrives on it. Without a sender in the
// packet the two attempts cannot tell their peers apart, and each may take the
// other's address -- which is worse than failing, since the address is learned
// and the edge reported direct, and the mistake only appears later when the far
// end answers with the wrong key.
//
// This is a label, not a credential. A fingerprint is public and anyone can put
// one in a packet; nothing is granted by doing so. What decides whether a path
// is used is still the TLS handshake against that key (D3), and a punch that
// lies about its sender achieves nothing beyond making one edge fall back to
// the relay -- which an attacker on the path could do by dropping packets
// anyway.
const punchLen = len(punchMagic) + sha256.Size

// punchFrom writes a punch packet identifying the sender.
func punchFrom(fingerprint string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(fingerprint)
	if err != nil || len(raw) != sha256.Size {
		return nil, fmt.Errorf("direct: %q is not a key fingerprint", fingerprint)
	}
	return append(punchMagic[:], raw...), nil
}

// punchSender reports which key sent a packet, and whether it was a punch.
func punchSender(b []byte) (string, bool) {
	if len(b) < punchLen || string(b[:len(punchMagic)]) != string(punchMagic[:]) {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(b[len(punchMagic):punchLen]), true
}

// Candidate is what one end tells the other about where it can be reached.
type Candidate struct {
	// Reflexive is the address the rendezvous saw, which is the mapping this
	// node's NAT presents to the outside.
	Reflexive string `json:"reflexive"`

	// Local is the address on this machine's own network. Two members behind
	// one router reach each other here without troubling any NAT, and a session
	// among housemates is not an unusual case.
	Local string `json:"local,omitempty"`

	// Fingerprint is the key that will answer on this path; see D3.
	Fingerprint string `json:"fingerprint"`
}

// Traverse tries to open a direct path to a peer and reports where it ended up.
//
// coord is an already-connected duplex stream to that peer — in a session, one
// relayed through the rendezvous. Using the relay to arrange its own replacement
// is deliberate: the two ends already have a working path to each other, so
// traversal needs no new operation on a service whose job is introduction, and
// it works identically for any pair however they were introduced.
//
// It returns the Peer to hand to Learn. ErrNoPath means the edge should be
// relayed — a normal outcome, not a failure.
func Traverse(ctx context.Context, coord net.Conn, e *Endpoint, mine Candidate, window time.Duration) (Peer, error) {
	theirs, err := exchange(ctx, coord, mine)
	if err != nil {
		return Peer{}, fmt.Errorf("direct: exchange candidates: %w", err)
	}
	if theirs.Fingerprint == "" {
		return Peer{}, errors.New("direct: the peer offered no key, so no path can be trusted")
	}

	// Every address the peer offered, most local first. A same-network pair
	// should not be sent out to a router and back, and trying local first costs
	// one packet if it is wrong.
	targets := make([]string, 0, 2)
	if theirs.Local != "" {
		targets = append(targets, theirs.Local)
	}
	if theirs.Reflexive != "" && theirs.Reflexive != theirs.Local {
		targets = append(targets, theirs.Reflexive)
	}
	if len(targets) == 0 {
		return Peer{}, ErrNoPath
	}

	addr, err := e.punch(ctx, targets, window, theirs.Fingerprint)
	if err != nil {
		return Peer{}, err
	}
	return Peer{Addr: addr, Fingerprint: theirs.Fingerprint}, nil
}

// exchange sends this end's candidate and reads the other's, at the same time.
//
// Both ends run this, so both write first and both read second — and writing
// before reading only works if the write completes without the far end having
// read yet. Over a relayed TCP stream it does, because a socket buffer absorbs a
// few hundred bytes. That is an assumption about the transport rather than
// anything this code guarantees, and a candidate set large enough to fill the
// buffer would deadlock two peers that were each waiting to be read.
//
// Sending concurrently removes the assumption. It is symmetric by construction:
// neither end is the initiator, which suits a swap where both have the same
// thing to say and neither is answering the other.
func exchange(ctx context.Context, coord net.Conn, mine Candidate) (Candidate, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = coord.SetDeadline(deadline)
		defer coord.SetDeadline(time.Time{})
	}

	sent := make(chan error, 1)
	go func() { sent <- json.NewEncoder(coord).Encode(mine) }()

	var theirs Candidate
	readErr := json.NewDecoder(coord).Decode(&theirs)

	if err := <-sent; err != nil {
		return Candidate{}, fmt.Errorf("send our candidate: %w", err)
	}
	if readErr != nil {
		return Candidate{}, fmt.Errorf("read theirs: %w", readErr)
	}
	return theirs, nil
}

// punch sends to every candidate address until one answers, and reports the
// address that did.
//
// The address that answers is not necessarily one that was offered. A NAT that
// maps per destination presents an address the peer could not have known to
// advertise, and the only place it appears is as the source of a packet that
// arrives here. That observed source — ICE calls it peer-reflexive — is what
// rescues the pairing the prediction expected to fail, so it is preferred over
// anything in the offer when the two disagree.
//
// Which is also why an arriving packet cannot be attributed by its address:
// the whole point is that it may come from somewhere unforeseen. expect is the
// peer's fingerprint, learned over the coordination stream, and it is what
// separates this attempt from any other running on the same socket.
func (e *Endpoint) punch(ctx context.Context, targets []string, window time.Duration, expect string) (string, error) {
	packet, err := punchFrom(e.id.Fingerprint)
	if err != nil {
		return "", err
	}
	addrs := make([]net.Addr, 0, len(targets))
	for _, t := range targets {
		a, err := net.ResolveUDPAddr("udp", t)
		if err != nil {
			slog.Debug("direct: unusable candidate", "address", t, "error", err)
			continue
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return "", ErrNoPath
	}
	slog.Debug("direct: punching", "from", e.tr.Conn.LocalAddr(), "targets", targets)

	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()

	heard := make(chan string, 4)
	stop := e.expectPunches(expect, heard)
	defer stop()

	// Repeat rather than send once. The first packet out of each side is
	// usually lost by construction — it arrives before the far mapping exists —
	// and the exchange above only loosely aligns the two ends, so the window
	// matters more than the instant.
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()

	send := func() {
		for _, a := range addrs {
			if _, err := e.tr.WriteTo(packet, a); err != nil {
				slog.Debug("direct: punch send failed", "to", a, "error", err)
			}
		}
	}

	var found string
	// linger keeps sending after this end is satisfied.
	//
	// Stopping the moment a packet arrives is the obvious thing and it starves
	// the peer: whoever hears first falls silent, and the other end waits out
	// its whole window hearing nothing. Both ends have to keep punching until
	// both are done, and neither can know when the other is — so the one that
	// finishes first keeps going a little longer, which is cheap and removes the
	// race entirely.
	const linger = 900 * time.Millisecond
	var lingerUntil time.Time

	for {
		send()
		select {
		case from := <-heard:
			if found == "" {
				found = from
				// Answer immediately as well as on the tick: the peer may be
				// one packet away from giving up.
				if a, err := net.ResolveUDPAddr("udp", from); err == nil {
					_, _ = e.tr.WriteTo(packet, a)
					addrs = append(addrs, a)
				}
				lingerUntil = time.Now().Add(linger)
			}
		case <-tick.C:
			if found != "" && time.Now().After(lingerUntil) {
				return found, nil
			}
		case <-ctx.Done():
			if found != "" {
				return found, nil
			}
			return "", ErrNoPath
		}
	}
}

// expectPunches says that this traversal wants the punches sent by expect, and
// returns the function that withdraws that interest.
//
// Registering rather than reading is what makes several attempts on one socket
// possible. A packet can only be read once, so an attempt that read the socket
// itself and discarded what was not its own would be destroying the packet the
// attempt beside it is waiting for -- two edges would starve each other and
// both fall back to the relay, on a machine where both direct paths were
// available.
func (e *Endpoint) expectPunches(expect string, heard chan<- string) func() {
	e.mu.Lock()
	e.listening[expect] = heard
	first := len(e.listening) == 1
	e.mu.Unlock()

	if first {
		go e.sortPunches()
	}
	return func() {
		e.mu.Lock()
		delete(e.listening, expect)
		e.mu.Unlock()
	}
}

// sortPunches reads traversal packets and hands each to whichever attempt is
// waiting for that sender.
//
// One reader for the socket, for as long as anything is traversing. It stops
// when nothing is left waiting, so a node that is not arranging an edge is not
// holding a read open on its own data plane.
func (e *Endpoint) sortPunches() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-e.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	buf := make([]byte, 64)
	for {
		e.mu.Lock()
		waiting := len(e.listening)
		e.mu.Unlock()
		if waiting == 0 {
			return
		}

		n, from, err := e.tr.ReadNonQUICPacket(ctx, buf)
		if err != nil {
			slog.Debug("direct: stopped listening for punches", "error", err)
			return
		}
		sender, ok := punchSender(buf[:n])
		if !ok {
			continue // something else entirely; not ours to interpret
		}

		e.mu.Lock()
		heard := e.listening[sender]
		e.mu.Unlock()
		if heard == nil {
			// Nobody is arranging an edge with that key: a straggler from an
			// attempt that has finished, or a stranger.
			slog.Debug("direct: a punch nobody is waiting for", "from", from, "sender", sender)
			continue
		}
		select {
		case heard <- from.String():
		default: // already known; the sender does not need telling twice
		}
	}
}
