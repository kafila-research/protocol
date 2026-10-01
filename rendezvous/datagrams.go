package rendezvous

import "net"

// Relayed datagrams: the server side.
//
// SKELETON. This file declares what the rendezvous's datagram relay must do
// and the names the rest of the package already calls. The implementation is
// to be written separately and reviewed against the tests in
// datagrams_test.go. Until it is, handle drops everything, members' Datagrams
// calls fail, and Kafila falls back to relaying rings over TCP as before.
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
// # What it must do
//
//   - Share the behaviour probe's primary UDP port. reach.ListenWith hands
//     handle every packet on that port that is not a probe; probes are JSON,
//     so a relay packet must never begin with '{'.
//   - Let a member register the UDP address it sends from, by presenting its
//     session ID, its peer ID and the RelayToken the rendezvous issued it at
//     host or join. Check the token with the token function given to
//     newDatagramRelay, in constant time, and acknowledge a good registration
//     so the member knows the relay is there. Ignore a bad one.
//   - Forward a member's packet to the member it names, only if both are
//     registered in the same session. The sender is identified by the address
//     the packet arrived from, never by anything it claims; the receiver is
//     told which member it came from.
//   - Forget a registration that has been idle for a while (members register
//     again periodically, which also keeps their NAT mappings open), and let a
//     member register again from a new address when its network changes.
//   - Never block the reading goroutine, never keep the packet buffer past
//     the call, and stay quiet in the logs at the info level: this carries
//     every token of every relayed ring.
//
// The framing is the implementer's to choose, and must match DatagramConn in
// datagram_conn.go.

// datagramRelay is the rendezvous's datagram relay.
type datagramRelay struct {
	// token reports the relay token issued to a peer in a session, and
	// whether that peer is a member of it (Server.memberToken).
	token func(session, peer string) (string, bool)

	// TODO: registrations, keyed both by member and by the address it
	// registered from, with when each was last heard.
}

// newDatagramRelay is a relay that checks registrations with token.
func newDatagramRelay(token func(session, peer string) (string, bool)) *datagramRelay {
	return &datagramRelay{token: token}
}

// handle takes one packet that arrived on the probe's primary port from from,
// and is not a probe. It runs on the port's reading goroutine; b is reused
// after it returns.
func (r *datagramRelay) handle(pc net.PacketConn, b []byte, from net.Addr) {
	// TODO: registration, acknowledgement and forwarding, as above.
}
