package direct

import (
	"context"
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

	addr, err := e.punch(ctx, targets, window)
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
func (e *Endpoint) punch(ctx context.Context, targets []string, window time.Duration) (string, error) {
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

	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()

	heard := make(chan string, 1)
	go e.listenForPunches(ctx, heard)

	// Repeat rather than send once. The first packet out of each side is
	// usually lost by construction — it arrives before the far mapping exists —
	// and the exchange above only loosely aligns the two ends, so the window
	// matters more than the instant.
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()

	for {
		for _, a := range addrs {
			if _, err := e.tr.WriteTo(punchMagic[:], a); err != nil {
				slog.Debug("direct: punch send failed", "to", a, "error", err)
			}
		}
		select {
		case from := <-heard:
			return from, nil
		case <-tick.C:
		case <-ctx.Done():
			return "", ErrNoPath
		}
	}
}

// listenForPunches reports the source of the first traversal packet to arrive.
func (e *Endpoint) listenForPunches(ctx context.Context, heard chan<- string) {
	buf := make([]byte, 64)
	for {
		n, from, err := e.tr.ReadNonQUICPacket(ctx, buf)
		if err != nil {
			return
		}
		if n < len(punchMagic) || string(buf[:len(punchMagic)]) != string(punchMagic[:]) {
			continue // something else entirely; not ours to interpret
		}
		select {
		case heard <- from.String():
		default:
		}
		return
	}
}
