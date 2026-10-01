package rendezvous

import (
	"errors"
	"net"
	"time"
)

// Relayed datagrams: the member side.
//
// SKELETON. This file declares the member's end of the datagram relay
// (datagrams.go) and the API Kafila builds on. The implementation is to be
// written separately and reviewed against the tests in datagrams_test.go.
// Until it is, Datagrams returns ErrNoDatagrams and callers relay over TCP.
//
// A DatagramConn is a net.PacketConn whose packets travel through the
// rendezvous to other members of this session, so that a QUIC endpoint
// (protocol/direct) can run over it unchanged: same identities, same pinned
// keys, a different route for the packets.
//
// # What it must do
//
//   - Open one UDP socket of its own and send to the rendezvous's UDP port,
//     which is the port number of Session.Addr (the behaviour probe's primary
//     port).
//   - Register with the session ID, this member's peer ID and its RelayToken,
//     and wait up to the timeout given to Datagrams for the relay to
//     acknowledge. No acknowledgement, a rendezvous that issued no token, or
//     UDP that does not get through, is ErrNoDatagrams: the caller relays
//     over TCP instead. Register again every few seconds while open, which
//     keeps the registration and this machine's NAT mapping alive.
//   - Give each peer a stand-in address (AddrOf) that is a valid *net.UDPAddr
//     in a range never routed (198.18.0.0/15), stable for the life of the
//     conn and distinct per peer, so that QUIC can address peers by it.
//     WriteTo sends to the peer a stand-in address names; ReadFrom returns
//     packets with the stand-in address of the member they came from.
//   - Ignore anything on the socket that does not come from the rendezvous or
//     is not a relayed packet, and never hand QUIC the relay's framing.
//   - Honour the deadline methods as a net.PacketConn must, since quic-go
//     relies on them, and stop registering when closed.
//
// The framing is the implementer's to choose, and must match datagrams.go.

// ErrNoDatagrams means the rendezvous does not relay datagrams for this member:
// it is too old to issue relay tokens, it did not acknowledge, or UDP to it
// is blocked. Rings then relay over TCP, as they did before.
var ErrNoDatagrams = errors.New("rendezvous: no datagram relay")

// DatagramConn carries packets to other members of a session through the
// rendezvous.
type DatagramConn struct {
	// TODO: the socket, the rendezvous's UDP address, this member's session,
	// peer ID and token, the stand-in addresses in both directions, and what
	// stops the re-registration when the conn is closed.
}

// Datagrams opens this member's datagram relay, waiting up to timeout for the
// rendezvous to acknowledge it.
func (s *Session) Datagrams(timeout time.Duration) (*DatagramConn, error) {
	// TODO: as above.
	return nil, ErrNoDatagrams
}

// AddrOf is the stand-in address that peer is reached at through this conn.
func (c *DatagramConn) AddrOf(peer string) net.Addr {
	// TODO: as above.
	return nil
}

// ReadFrom reads the next packet relayed to this member, and the stand-in
// address of the member that sent it.
func (c *DatagramConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, ErrNoDatagrams // TODO
}

// WriteTo sends p to the member whose stand-in address addr is.
func (c *DatagramConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, ErrNoDatagrams // TODO
}

// Close stops relaying for this member and closes the socket.
func (c *DatagramConn) Close() error { return nil } // TODO

// LocalAddr is the socket's own address.
func (c *DatagramConn) LocalAddr() net.Addr { return nil } // TODO

func (c *DatagramConn) SetDeadline(t time.Time) error      { return ErrNoDatagrams } // TODO
func (c *DatagramConn) SetReadDeadline(t time.Time) error  { return ErrNoDatagrams } // TODO
func (c *DatagramConn) SetWriteDeadline(t time.Time) error { return ErrNoDatagrams } // TODO

var _ net.PacketConn = (*DatagramConn)(nil)
