package reach

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// Filtering has to be tested before anything is sent to the alt address.
//
// The two tests share one socket, and the mapping test sends to the very
// endpoint the filtering test then expects to hear from. In that order it opens
// a pinhole for that exact endpoint, so the reply arrives on any network keeping
// state per destination — and every NAT with endpoint-independent mapping
// reports endpoint-independent filtering, which is to say every one of them
// looks permissive.
//
// The distinction being drawn is between a network that admits a stranger and
// one that admits a correspondent. Writing first turns the stranger into a
// correspondent, and the measurement stops meaning anything.
//
// Found in emulation: a NAT built to be port-restricted measured as permissive,
// and the router was not the thing that was wrong.
//
// The check is on the socket rather than on the server, because the property is
// about what this socket has written to: an alt address that has never been
// sent to cannot have a pinhole open for it.
func TestNothingIsSentToTheAltAddressBeforeFilteringIsTested(t *testing.T) {
	s, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	primary, alt := s.Addrs()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	watched := &watcher{PacketConn: pc, alt: alt}
	b, err := Probe(watched, primary, alt, 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	if !watched.altWritten {
		t.Fatal("the mapping test never ran; this test would pass vacuously")
	}
	if b.Filtering == FilteringUnknown {
		t.Fatal("filtering was never determined")
	}
	if watched.altBeforeFilter {
		t.Error("the alt address was written to before filtering was tested: " +
			"the pinhole that opens is the thing the filtering test detects, so every " +
			"endpoint-independent-mapping network would report permissive")
	}
}

// watcher records whether the socket wrote to the alt address, and whether it
// did so before the filtering request went out.
type watcher struct {
	net.PacketConn
	alt string

	filterAsked     bool
	altWritten      bool
	altBeforeFilter bool
}

func (w *watcher) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr.String() == w.alt {
		w.altWritten = true
		if !w.filterAsked {
			w.altBeforeFilter = true
		}
	}
	// The filtering request is the one that asks for a reply from elsewhere.
	var sent probe
	if err := json.Unmarshal(p, &sent); err == nil && sent.Alt {
		w.filterAsked = true
	}
	return w.PacketConn.WriteTo(p, addr)
}

func (w *watcher) SetReadDeadline(t time.Time) error { return w.PacketConn.SetReadDeadline(t) }
