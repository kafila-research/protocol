// Package reach works out what a machine's network does to outbound UDP, which
// is what decides whether two members of a session can talk directly.
//
// Two properties matter, and they are independent (RFC 4787):
//
//   - mapping — does the same local socket get the same external address and
//     port whatever it talks to, or a fresh one per destination? A fresh one per
//     destination is what defeats hole punching, because the address the far
//     side was told to aim at is not the one that will be used to reach it.
//
//   - filtering — once a mapping exists, may anyone send to it, or only the
//     endpoints already written to? Filtering decides the hard cases: a
//     permissive filter on one side rescues a restrictive mapping on the other,
//     and without it that pairing has no direct path at all.
//
// # Why not a public STUN server
//
// Discovering filtering needs a server that will answer from an address the
// client has not written to (RFC 5780's CHANGE-REQUEST). Public STUN servers
// mostly do not, and the ones that do are inconsistent about it. Since a session
// already has a rendezvous both sides reach outbound, that service can answer
// from a second port and give a straight answer instead of an inference.
//
// # What one address cannot tell you
//
// Answering from a second *port* on the same address separates
// port-dependent behaviour from endpoint-independent. Separating
// address-dependent from port-dependent as well would need the server to hold
// two addresses. That distinction does not change whether hole punching works,
// so it is not attempted, and the classification says which of the two it is
// reporting rather than implying a precision it does not have.
package reach

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"time"
)

// Mapping is what the network does to a socket's external address.
type Mapping string

const (
	// MappingEndpointIndependent: one external address and port, whatever the
	// destination. Hole punching works.
	MappingEndpointIndependent Mapping = "endpoint-independent"
	// MappingPortDependent: a fresh external port per destination. The far side
	// cannot be told where to aim, so hole punching fails unless the other end
	// filters permissively.
	MappingPortDependent Mapping = "port-dependent"
	MappingUnknown       Mapping = "unknown"
)

// Filtering is what the network lets back in.
type Filtering string

const (
	// FilteringEndpointIndependent: anyone may send to an open mapping. This is
	// the property that rescues a port-dependent peer on the other side.
	FilteringEndpointIndependent Filtering = "endpoint-independent"
	// FilteringPortRestricted: only endpoints already written to may reply.
	FilteringPortRestricted Filtering = "port-restricted"
	FilteringUnknown        Filtering = "unknown"
)

// Behaviour is one machine's report about its own network.
type Behaviour struct {
	Mapping   Mapping   `json:"mapping"`
	Filtering Filtering `json:"filtering"`

	// Reflexive is the external address the rendezvous saw, kept so two members
	// behind one router can be recognised as such — they need no traversal at
	// all and would otherwise flatter any measurement they appear in.
	Reflexive string `json:"reflexive,omitempty"`

	// UDPBlocked is set when nothing came back at all. It is a different
	// finding from a restrictive NAT and must not be folded into one.
	UDPBlocked bool `json:"udp_blocked,omitempty"`

	// Evidence records what the classification rests on, so it can be checked
	// without being rerun.
	Evidence Evidence `json:"evidence"`
}

// Evidence is the raw observation behind a Behaviour.
type Evidence struct {
	MappedPrimary string `json:"mapped_primary,omitempty"`
	MappedAlt     string `json:"mapped_alt,omitempty"`
	AltReplyHeard bool   `json:"alt_reply_heard"`
	RoundTripMs   int64  `json:"round_trip_ms,omitempty"`
}

// Class is where a machine sits in the three-way split that decides whether a
// pair can find a direct path.
type Class string

const (
	// ClassPermissive filters endpoint-independently. It can reach anyone,
	// including a restrictive peer.
	ClassPermissive Class = "permissive"
	// ClassOrdinary maps endpoint-independently but filters strictly. It can
	// reach anything except a restrictive peer.
	ClassOrdinary Class = "ordinary"
	// ClassRestrictive maps per destination. It can only be reached by a
	// permissive peer.
	ClassRestrictive Class = "restrictive"
	ClassUnknown     Class = "unknown"
)

// Classify places a behaviour in the three-way split.
func (b Behaviour) Classify() Class {
	switch {
	case b.UDPBlocked || b.Mapping == MappingUnknown:
		return ClassUnknown
	case b.Filtering == FilteringEndpointIndependent:
		return ClassPermissive
	case b.Mapping == MappingPortDependent:
		return ClassRestrictive
	default:
		return ClassOrdinary
	}
}

// CanReach reports whether two machines should find a direct path, from their
// classes alone.
//
// A restrictive machine can only be reached by a permissive one: its mapping
// toward the far side is not the mapping anyone was told about, so the only way
// the far side can answer is to have let in a packet from an address it never
// wrote to. Everything else pairs.
//
// This is a prediction, not a promise. Real equipment has behaviours no
// standard describes, so a plan built on it should verify the edges it actually
// uses and record where the prediction was wrong — that error rate is worth
// knowing.
func CanReach(a, b Class) bool {
	if a == ClassUnknown || b == ClassUnknown {
		return false
	}
	if a == ClassRestrictive && b == ClassRestrictive {
		return false
	}
	if a == ClassRestrictive || b == ClassRestrictive {
		return a == ClassPermissive || b == ClassPermissive
	}
	return true
}

// probe is the request a client sends. Alt asks the server to answer from its
// second port instead of the one addressed, which is the filtering test.
type probe struct {
	Token string `json:"token"`
	Alt   bool   `json:"alt"`
}

// reply is what the server sends back.
type reply struct {
	Token  string `json:"token"`
	Mapped string `json:"mapped"`
	From   string `json:"from"` // primary | alt
}

// Probe measures this machine's behaviour against a rendezvous.
//
// Everything goes out of one socket, because a mapping belongs to a source
// tuple: a second socket would create a second mapping and the comparison would
// mean nothing.
func Probe(primary, alt string, timeout time.Duration) (Behaviour, error) {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return Behaviour{}, err
	}
	defer pc.Close()

	primaryAddr, err := net.ResolveUDPAddr("udp", primary)
	if err != nil {
		return Behaviour{}, fmt.Errorf("reach: primary %q: %w", primary, err)
	}
	altAddr, err := net.ResolveUDPAddr("udp", alt)
	if err != nil {
		return Behaviour{}, fmt.Errorf("reach: alt %q: %w", alt, err)
	}

	b := Behaviour{Mapping: MappingUnknown, Filtering: FilteringUnknown}
	started := time.Now()

	// 1. What does the primary port see us as?
	r1, err := exchange(pc, primaryAddr, probe{Token: "p", Alt: false}, timeout)
	if err != nil {
		b.UDPBlocked = true
		return b, nil // not an error: a blocked network is a finding
	}
	b.Reflexive = r1.Mapped
	b.Evidence.MappedPrimary = r1.Mapped
	b.Evidence.RoundTripMs = time.Since(started).Milliseconds()

	// 2. What does a different port on the same server see us as? A different
	//    mapping here means a fresh one per destination.
	r2, err := exchange(pc, altAddr, probe{Token: "a", Alt: false}, timeout)
	if err == nil {
		b.Evidence.MappedAlt = r2.Mapped
		if r2.Mapped == r1.Mapped {
			b.Mapping = MappingEndpointIndependent
		} else {
			b.Mapping = MappingPortDependent
		}
	}

	// 3. Ask the primary port to answer from the alt port. Hearing that reply
	//    means the network admits packets from an address this socket never
	//    wrote to, which is what lets a restrictive peer through.
	_, err = exchange(pc, primaryAddr, probe{Token: "f", Alt: true}, timeout)
	if err == nil {
		b.Evidence.AltReplyHeard = true
		b.Filtering = FilteringEndpointIndependent
	} else {
		b.Filtering = FilteringPortRestricted
	}

	return b, nil
}

func exchange(pc net.PacketConn, to net.Addr, p probe, timeout time.Duration) (reply, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return reply{}, err
	}

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 1500)
	// Retried because a single lost datagram would otherwise be recorded as a
	// restrictive network, which is the error this measurement can least afford.
	for attempt := 0; attempt < 3 && time.Now().Before(deadline); attempt++ {
		if _, err := pc.WriteTo(body, to); err != nil {
			return reply{}, err
		}
		_ = pc.SetReadDeadline(time.Now().Add(timeout / 3))
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				break // timed out on this attempt; try again
			}
			var r reply
			if json.Unmarshal(buf[:n], &r) != nil {
				continue
			}
			if r.Token != p.Token {
				continue // a straggler from an earlier probe
			}
			return r, nil
		}
	}
	return reply{}, fmt.Errorf("reach: no reply to probe %q", p.Token)
}

// ProbeVia measures this machine against a rendezvous, given the address
// already used to reach it.
//
// The probe ports are derived rather than configured: the rendezvous answers
// control on TCP at its port and behaviour probes on UDP at the same number and
// the one above. A session already knows that address, so nobody has to be told
// a second one, and there is no round trip to learn it before the measurement
// that has to happen before joining.
func ProbeVia(rendezvous string, timeout time.Duration) (Behaviour, error) {
	host, portStr, err := net.SplitHostPort(rendezvous)
	if err != nil {
		return Behaviour{}, fmt.Errorf("reach: rendezvous address %q: %w", rendezvous, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return Behaviour{}, fmt.Errorf("reach: port in %q: %w", rendezvous, err)
	}
	return Probe(
		net.JoinHostPort(host, fmt.Sprint(port)),
		net.JoinHostPort(host, fmt.Sprint(port+1)),
		timeout,
	)
}

// Pair is a predicted verdict about one edge.
type Pair struct {
	A      string `json:"a"`
	B      string `json:"b"`
	Direct bool   `json:"direct"`
}

// Predict applies the pairing rule across a set of members.
//
// It is arithmetic over a small table rather than packets: each machine was
// probed once, so a session of any size costs a linear number of measurements
// and this costs none at all. Predictions want verifying against the edges a
// plan actually uses, and where one turns out wrong that is worth recording —
// the rate at which the rule mispredicts real equipment is not known.
func Predict(classes map[string]Class) []Pair {
	names := make([]string, 0, len(classes))
	for n := range classes {
		names = append(names, n)
	}
	sort.Strings(names)

	var out []Pair
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			out = append(out, Pair{
				A: names[i], B: names[j],
				Direct: CanReach(classes[names[i]], classes[names[j]]),
			})
		}
	}
	return out
}

// RingFeasible reports whether an ordering exists in which every edge is
// direct, and how many machines force a relay if not.
//
// A restrictive machine needs a permissive neighbour on both sides, and a
// permissive machine can serve two of them, so the question is a count: are
// there at least as many permissive machines as restrictive ones. No search is
// involved and the answer does not get harder as a session grows.
func RingFeasible(classes map[string]Class) (feasible bool, permissive, restrictive int) {
	for _, c := range classes {
		switch c {
		case ClassPermissive:
			permissive++
		case ClassRestrictive, ClassUnknown:
			// Unknown counts as restrictive: planning optimistically on a
			// machine nothing is known about is how a session ends up with an
			// edge that cannot carry anything.
			restrictive++
		}
	}
	return permissive >= restrictive, permissive, restrictive
}
