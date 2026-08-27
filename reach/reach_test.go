package reach

import (
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
	b, err := Probe(primary, alt, 2*time.Second)
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
	b, err := Probe("127.0.0.1:9", "127.0.0.1:10", 300*time.Millisecond)
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
	feasible := func(permissive, ordinary, restrictive int) bool {
		_ = ordinary // ordinary machines pair with everything except restrictive
		return permissive >= restrictive
	}
	cases := []struct {
		p, o, r int
		want    bool
	}{
		{2, 0, 0, true},
		{0, 4, 0, true},
		{1, 2, 1, true},
		{0, 3, 1, false},
		{2, 0, 3, false},
	}
	for _, c := range cases {
		if got := feasible(c.p, c.o, c.r); got != c.want {
			t.Errorf("%d permissive, %d ordinary, %d restrictive: got %v, want %v", c.p, c.o, c.r, got, c.want)
		}
	}
}
