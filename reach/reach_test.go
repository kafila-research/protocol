package reach

import (
	"net"
	"testing"
	"time"
)

// On loopback there is no NAT at all, so the probe should report the permissive
// end of every axis. It is a weak network but a strong check on the instrument:
// if this does not come back permissive, the measurement is broken and every
// figure it produces later is worthless.
func TestLoopbackLooksPermissive(t *testing.T) {
	s, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	primary, alt := s.Addrs()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer pc.Close()

	b, err := Probe(pc, primary, alt, 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	if b.UDPBlocked {
		t.Fatal("loopback reported UDP as blocked")
	}
	if b.Mapping != MappingEndpointIndependent {
		t.Errorf("mapping %q, want endpoint-independent (evidence: %+v)", b.Mapping, b.Evidence)
	}
	if b.Filtering != FilteringEndpointIndependent {
		t.Errorf("filtering %q, want endpoint-independent — the alt-port reply should arrive on loopback", b.Filtering)
	}
	if !b.Evidence.AltReplyHeard {
		t.Error("the alt-port reply was not heard, so filtering was inferred rather than observed")
	}
	if got := b.Classify(); got != ClassPermissive {
		t.Errorf("class %q, want permissive", got)
	}
	if b.Reflexive == "" {
		t.Error("no reflexive address recorded")
	}
}

// A blocked network is a different finding from a restrictive one and must not
// be reported as a NAT behaviour.
func TestNoServerReportsBlockedRatherThanRestrictive(t *testing.T) {
	// Nothing is listening here.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer pc.Close()

	b, err := Probe(pc, "127.0.0.1:9", "127.0.0.1:10", 300*time.Millisecond)
	if err != nil {
		t.Fatalf("probe returned an error rather than a finding: %v", err)
	}
	if !b.UDPBlocked {
		t.Error("silence was not reported as blocked")
	}
	if got := b.Classify(); got != ClassUnknown {
		t.Errorf("class %q, want unknown — nothing was learned", got)
	}
}

// The pairing rule the planner will use. A restrictive machine can only be
// reached by a permissive one; everything else pairs.
func TestWhoCanReachWhom(t *testing.T) {
	cases := []struct {
		a, b Class
		want bool
	}{
		{ClassPermissive, ClassPermissive, true},
		{ClassPermissive, ClassOrdinary, true},
		{ClassPermissive, ClassRestrictive, true}, // the rescue
		{ClassOrdinary, ClassOrdinary, true},
		{ClassOrdinary, ClassRestrictive, false},
		{ClassRestrictive, ClassRestrictive, false},
		{ClassUnknown, ClassPermissive, false},
	}
	for _, c := range cases {
		if got := CanReach(c.a, c.b); got != c.want {
			t.Errorf("CanReach(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
		if got := CanReach(c.b, c.a); got != c.want {
			t.Errorf("CanReach is not symmetric: (%s, %s) = %v, want %v", c.b, c.a, got, c.want)
		}
	}
}

// An all-direct ring exists exactly when there are at least as many permissive
// machines as restrictive ones, since each restrictive one needs a permissive
// neighbour on both sides and each permissive one can serve two.
func TestRingFeasibilityIsACount(t *testing.T) {
	// Calls the real function. The version of this test that shipped first
	// declared a local copy of the rule and checked that against expectations
	// derived from the same rule, so it asserted nothing and could not fail —
	// and it carried {1 permissive, 2 ordinary, 1 restrictive: feasible}, which
	// is one of the cases the rule was wrong about.
	cases := []struct {
		p, o, r int
		want    bool
	}{
		{2, 0, 0, true},  // nothing restrictive to place
		{0, 4, 0, true},  // ordinary machines pair with each other
		{2, 0, 2, true},  // a tight alternation, and nothing to disturb it
		{1, 2, 1, false}, // the ordinary machines have nowhere to go but beside the restrictive one
		{2, 1, 1, true},  // one permissive to spare, so the ordinary machine has a home
		{0, 3, 1, false}, // nothing permissive at all
		{2, 0, 3, false}, // more restrictive machines than permissive ones
	}

	for _, c := range cases {
		classes := map[string]Class{}
		id := 0
		add := func(n int, cl Class) {
			for range n {
				classes[string(rune('a'+id))] = cl
				id++
			}
		}
		add(c.p, ClassPermissive)
		add(c.o, ClassOrdinary)
		add(c.r, ClassRestrictive)

		got, counts := RingFeasible(classes)
		if got != c.want {
			t.Errorf("%d permissive, %d ordinary, %d restrictive: got %v, want %v (counts %+v)",
				c.p, c.o, c.r, got, c.want, counts)
		}
	}
}

// The reflexive address must describe the socket that was handed in.
//
// This is the property hole punching rests on. A mapping belongs to a source
// tuple, so telling a peer to aim at an address measured from some other socket
// points it at a mapping the data will never use. On loopback there is no NAT to
// translate anything, so the reflexive port must be exactly the local one — and
// if it is not, the probe is describing a socket other than the caller's.
func TestTheReflexiveAddressIsAboutTheCallersSocket(t *testing.T) {
	s, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	primary, alt := s.Addrs()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer pc.Close()

	b, err := Probe(pc, primary, alt, 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	_, want, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := net.SplitHostPort(b.Reflexive)
	if err != nil {
		t.Fatalf("reflexive %q: %v", b.Reflexive, err)
	}
	if got != want {
		t.Fatalf("reflexive port %s, but the caller's socket is on %s: the probe measured a different socket", got, want)
	}
}

// The feasibility rule must agree with an exhaustive search over orderings.
//
// The first version of it said an all-direct ring exists whenever there are at
// least as many permissive machines as restrictive ones. That is wrong whenever
// an ordinary machine is present and the two exactly balance: the ring is then a
// tight alternation with every permissive adjacency spoken for, and the ordinary
// machine has nowhere to go but beside a restrictive one.
//
// It was found by searching, not by thinking, which is why the search is kept.
func TestFeasibilityAgreesWithExhaustiveSearch(t *testing.T) {
	for p := 0; p <= 4; p++ {
		for m := 0; m <= 3; m++ {
			for h := 0; h <= 4; h++ {
				n := p + m + h
				if n < 3 || n > 7 {
					continue
				}
				ring := make([]Class, 0, n)
				for range p {
					ring = append(ring, ClassPermissive)
				}
				for range m {
					ring = append(ring, ClassOrdinary)
				}
				for range h {
					ring = append(ring, ClassRestrictive)
				}

				classes := map[string]Class{}
				for i, c := range ring {
					classes[string(rune('a'+i))] = c
				}
				got, counts := RingFeasible(classes)

				if want := anyRingAllDirect(ring); got != want {
					t.Errorf("P=%d M=%d H=%d: rule says %v, search says %v (counts %+v)",
						p, m, h, got, want, counts)
				}
			}
		}
	}
}

// anyRingAllDirect is true when some ordering has every edge direct.
func anyRingAllDirect(ring []Class) bool {
	perm := append([]Class{}, ring...)
	found := false

	var walk func(at int)
	walk = func(at int) {
		if found {
			return
		}
		if at == len(perm) {
			for i := range perm {
				if !CanReach(perm[i], perm[(i+1)%len(perm)]) {
					return
				}
			}
			found = true
			return
		}
		for i := at; i < len(perm); i++ {
			perm[at], perm[i] = perm[i], perm[at]
			walk(at + 1)
			perm[at], perm[i] = perm[i], perm[at]
		}
	}
	walk(0)
	return found
}
