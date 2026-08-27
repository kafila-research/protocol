// Command rendezvous runs the session rendezvous on its own.
//
// The same service is available from the main binary as
// `ollama runner --session --serve-rendezvous`, and for a machine that is
// already set up to run a shard that is the better way to reach it: one
// artifact, nothing extra to build.
//
// This exists because the machine that should run a rendezvous is the opposite
// kind of machine. It wants to be always-on, cheap, and somewhere both parties
// can reach outbound — a free-tier cloud instance with a gigabyte of memory and
// no GPU. The main binary links MLX through cgo, so building it needs a GPU
// toolchain the rendezvous will never call, and cross-compiling it needs that
// toolchain for the target as well. Neither is reasonable to ask of a host
// whose entire job is to copy bytes between two sockets.
//
// The rendezvous imports nothing but the standard library and the reachability
// probe, so on its own it builds with CGO_ENABLED=0 into a static binary that
// runs anywhere, and there is no glibc version to match between the machine
// that built it and the machine that runs it.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/kafila-research/protocol/rendezvous"
)

func main() {
	addr := flag.String("addr", ":443", "address to serve on; the UDP port above this one must also be open")
	debug := flag.String("log", "info", "log level: debug, info, warn, error")
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*debug)); err != nil {
		fmt.Fprintf(os.Stderr, "rendezvous: %v\n", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rendezvous: listen on %s: %v\n", *addr, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr,
		"\n  rendezvous on %s\n  hosts and members reach it outbound; neither has to be reachable\n\n",
		ln.Addr())

	// Shut down on a signal rather than being killed, so a restart does not
	// leave sessions wondering. Closing the listener is what ends Serve.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		slog.Info("rendezvous: shutting down")
		ln.Close()
	}()

	srv := rendezvous.NewServer()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "rendezvous: %v\n", err)
		os.Exit(1)
	}
}
