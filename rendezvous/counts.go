package rendezvous

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// What the rendezvous relayed, said once a minute while it relays anything.
//
// The first alpha's prompts crawled across relayed links, and nothing the
// rendezvous logged could say whether it was the cause: its one sign of
// trouble, a full datagram write queue, was logged at Debug and never left the
// machine. These are counted instead, and a minute's worth is logged at Info,
// which is what reaches telemetry.
type relayCounts struct {
	datagrams, datagramBytes atomic.Int64
	// Datagrams not relayed, by why: the write queue was full, the sender had
	// not registered, the receiver had not, or the write failed.
	queueFull, unknownSender, unknownReceiver, writeFailed atomic.Int64

	streams, streamBytes atomic.Int64
	streamsOpen          atomic.Int64
}

// countsEvery is how often a minute's counts are reported.
const countsEvery = time.Minute

// report logs what was relayed since last, at Info, unless nothing was, and
// returns the totals to report the next minute against.
func (c *relayCounts) report(last [8]int64) [8]int64 {
	now := [8]int64{
		c.datagrams.Load(), c.datagramBytes.Load(),
		c.queueFull.Load(), c.unknownSender.Load(), c.unknownReceiver.Load(), c.writeFailed.Load(),
		c.streams.Load(), c.streamBytes.Load(),
	}
	if now == last {
		return now
	}
	d := func(i int) int64 { return now[i] - last[i] }
	slog.Info("rendezvous: relayed in the last minute",
		"datagrams", d(0), "datagram_bytes", d(1),
		"dropped_queue_full", d(2), "dropped_unknown_sender", d(3),
		"dropped_unknown_receiver", d(4), "dropped_write_failed", d(5),
		"streams", d(6), "stream_bytes", d(7), "streams_open", c.streamsOpen.Load())
	return now
}

// reportCounts reports every countsEvery until done is closed.
func (c *relayCounts) reportCounts(done <-chan struct{}) {
	tick := time.NewTicker(countsEvery)
	defer tick.Stop()
	var last [8]int64
	for {
		select {
		case <-done:
			c.report(last)
			return
		case <-tick.C:
			last = c.report(last)
		}
	}
}
