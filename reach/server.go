package reach

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
)

// Server answers behaviour probes from two ports.
//
// The second port is the whole point. Answering a probe from a port the client
// never wrote to is the only way to find out whether its network will let such a
// packet in, and that property is what decides the hard pairings. A service that
// answered only from the port addressed could report what a machine's mapping
// does and would have nothing to say about its filtering.
type Server struct {
	primary, alt net.PacketConn
}

// Listen binds both ports. The alt port is the one after the primary, which
// keeps deployment to a single decision and a single firewall rule.
func Listen(address string) (*Server, error) {
	primary, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, fmt.Errorf("reach: listen on %s: %w", address, err)
	}

	// The alt port is derived from the port actually bound, not from the one
	// asked for. With port 0 the operating system chooses, and computing an
	// alt from the request would try to bind port 1.
	bound, ok := primary.LocalAddr().(*net.UDPAddr)
	if !ok {
		primary.Close()
		return nil, fmt.Errorf("reach: unexpected address type %T", primary.LocalAddr())
	}

	// The two ports have to be on the same address for the filtering test to
	// mean anything: the point is a reply from somewhere this client has not
	// written to, while everything else stays equal.
	var alt net.PacketConn
	for offset := 1; offset <= 8; offset++ {
		altAddr := &net.UDPAddr{IP: bound.IP, Port: bound.Port + offset}
		alt, err = net.ListenPacket("udp", altAddr.String())
		if err == nil {
			break
		}
	}
	if alt == nil {
		primary.Close()
		return nil, fmt.Errorf("reach: no free alt port near %d: %w", bound.Port, err)
	}

	s := &Server{primary: primary, alt: alt}
	go s.serve(primary, "primary")
	go s.serve(alt, "alt")
	slog.Info("behaviour probe listening", "primary", primary.LocalAddr(), "alt", alt.LocalAddr())
	return s, nil
}

// ServeOn answers on sockets the caller already holds.
//
// The mirror of Probe taking the caller's socket, and for the same reason: the
// answer a probe gets is about the path between two particular sockets, so both
// ends have to be substitutable. Binding them here would make this measurable
// only over whatever the operating system happens to provide.
//
// What that buys is a simulated network. An emulator can hand both ends a
// PacketConn on a synthetic link with a stated NAT behaviour in between, and the
// same classifier that runs in the field then runs over the whole RFC 4787
// matrix -- including the combinations no set of real networks will offer on
// demand.
//
// The two sockets must be reachable at addresses differing only in port, or the
// filtering test stops meaning what it says: it asks for a reply from somewhere
// the client has not written to, while everything else stays equal.
func ServeOn(primary, alt net.PacketConn) *Server {
	s := &Server{primary: primary, alt: alt}
	go s.serve(primary, "primary")
	go s.serve(alt, "alt")
	return s
}

// Addrs reports where clients should send, primary first.
func (s *Server) Addrs() (string, string) {
	return s.primary.LocalAddr().String(), s.alt.LocalAddr().String()
}

func (s *Server) Close() error {
	s.primary.Close()
	return s.alt.Close()
}

func (s *Server) serve(pc net.PacketConn, name string) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var p probe
		if json.Unmarshal(buf[:n], &p) != nil {
			continue
		}

		// The mapped address is always what this server observed, never what
		// the client believed: behind NAT the client cannot know it, and a
		// self-reported one would be a lie from anyone hostile.
		out, err := json.Marshal(reply{Token: p.Token, Mapped: from.String(), From: name})
		if err != nil {
			continue
		}

		// Answering from the other port is the filtering test. If the client
		// never hears it, that silence is the result.
		via := pc
		if p.Alt && name == "primary" {
			via = s.alt
		}
		if _, err := via.WriteTo(out, from); err != nil {
			slog.Debug("reach: reply failed", "to", from, "error", err)
		}
	}
}
