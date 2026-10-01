package rendezvous

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
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

const (
	datagramRegisterInterval = 3 * time.Second
	datagramRegisterRetry    = 250 * time.Millisecond
)

// ErrNoDatagrams means the rendezvous does not relay datagrams for this member:
// it is too old to issue relay tokens, it did not acknowledge, or UDP to it
// is blocked. Rings then relay over TCP, as they did before.
var ErrNoDatagrams = errors.New("rendezvous: no datagram relay")

// DatagramConn carries packets to other members of a session through the
// rendezvous.
type DatagramConn struct {
	pc      net.PacketConn
	relay   *net.UDPAddr
	session string
	peer    string
	token   string

	done chan struct{}
	once sync.Once

	mu            sync.Mutex
	standinByPeer map[string]*net.UDPAddr
	peerByStandin map[string]string
	nextStandin   uint32
}

// Datagrams opens this member's datagram relay, waiting up to timeout for the
// rendezvous to acknowledge it.
func (s *Session) Datagrams(timeout time.Duration) (*DatagramConn, error) {
	if s.RelayToken == "" {
		return nil, ErrNoDatagrams
	}
	relay, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDatagrams, err)
	}
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDatagrams, err)
	}

	c := &DatagramConn{
		pc:            pc,
		relay:         relay,
		session:       s.ID,
		peer:          s.PeerID,
		token:         s.RelayToken,
		done:          make(chan struct{}),
		standinByPeer: map[string]*net.UDPAddr{},
		peerByStandin: map[string]string{},
	}

	if err := c.awaitAck(timeout); err != nil {
		_ = pc.Close()
		return nil, err
	}

	go c.reregister()
	return c, nil
}

func (c *DatagramConn) registrationFrame() []byte {
	frame := []byte{datagramFrameRegister}
	frame = appendDatagramField(frame, c.session)
	frame = appendDatagramField(frame, c.peer)
	frame = appendDatagramField(frame, c.token)
	return frame
}

func (c *DatagramConn) registerOnce() error {
	_, err := c.pc.WriteTo(c.registrationFrame(), c.relay)
	return err
}

func (c *DatagramConn) awaitAck(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)

	for {
		now := time.Now()
		if !now.Before(deadline) {
			return ErrNoDatagrams
		}
		_ = c.registerOnce()

		next := now.Add(datagramRegisterRetry)
		if next.After(deadline) {
			next = deadline
		}
		if err := c.pc.SetReadDeadline(next); err != nil {
			return fmt.Errorf("%w: %v", ErrNoDatagrams, err)
		}

		for {
			n, from, err := c.pc.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				return fmt.Errorf("%w: %v", ErrNoDatagrams, err)
			}
			if !udpAddrEqual(from, c.relay) || n == 0 || buf[0] != datagramFrameAck {
				continue
			}
			_ = c.pc.SetReadDeadline(time.Time{})
			return nil
		}
	}
}

func (c *DatagramConn) reregister() {
	t := time.NewTicker(datagramRegisterInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			_ = c.registerOnce()
		}
	}
}

func udpAddrEqual(a net.Addr, b *net.UDPAddr) bool {
	u, ok := a.(*net.UDPAddr)
	if !ok {
		return false
	}
	return u.Port == b.Port && u.IP.Equal(b.IP)
}

func standinKey(a *net.UDPAddr) string {
	return a.IP.String() + ":" + strconv.Itoa(a.Port)
}

func nextStandin(idx uint32) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IPv4(198, 18+byte((idx>>16)&1), byte((idx>>8)&0xff), byte(idx&0xff)),
		Port: 1,
	}
}

func (c *DatagramConn) standinForPeer(peer string) *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if addr, ok := c.standinByPeer[peer]; ok {
		return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
	}
	for {
		addr := nextStandin(c.nextStandin)
		c.nextStandin++
		key := standinKey(addr)
		if _, used := c.peerByStandin[key]; used {
			continue
		}
		c.standinByPeer[peer] = addr
		c.peerByStandin[key] = peer
		return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
	}
}

// AddrOf is the stand-in address that peer is reached at through this conn.
func (c *DatagramConn) AddrOf(peer string) net.Addr {
	return c.standinForPeer(peer)
}

func parseRelayedDatagram(frame []byte) (string, []byte, bool) {
	if len(frame) == 0 || frame[0] != datagramFrameFromPeer {
		return "", nil, false
	}
	at := 1
	peer, ok := parseDatagramField(frame, &at)
	if !ok {
		return "", nil, false
	}
	return peer, frame[at:], true
}

// ReadFrom reads the next packet relayed to this member, and the stand-in
// address of the member that sent it.
func (c *DatagramConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65536)
	for {
		n, from, err := c.pc.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if !udpAddrEqual(from, c.relay) {
			continue
		}
		peer, payload, ok := parseRelayedDatagram(buf[:n])
		if !ok {
			continue
		}
		n = copy(p, payload)
		return n, c.standinForPeer(peer), nil
	}
}

// WriteTo sends p to the member whose stand-in address addr is.
func (c *DatagramConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	u, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.InvalidAddrError("rendezvous: destination is not a UDP address")
	}

	c.mu.Lock()
	peer, ok := c.peerByStandin[standinKey(u)]
	c.mu.Unlock()
	if !ok {
		return 0, net.InvalidAddrError("rendezvous: destination is not one of this session's stand-in addresses")
	}

	frame := make([]byte, 0, 2+len(peer)+len(p))
	frame = append(frame, datagramFrameToPeer)
	frame = appendDatagramField(frame, peer)
	frame = append(frame, p...)

	if _, err := c.pc.WriteTo(frame, c.relay); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close stops relaying for this member and closes the socket.
func (c *DatagramConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.pc.Close()
}

// LocalAddr is the socket's own address.
func (c *DatagramConn) LocalAddr() net.Addr { return c.pc.LocalAddr() }

func (c *DatagramConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *DatagramConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *DatagramConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }

var _ net.PacketConn = (*DatagramConn)(nil)
