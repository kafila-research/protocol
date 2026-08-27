# The rendezvous, and nothing else.
#
# It holds no model and runs no inference, so this image needs neither a GPU nor
# any native library — which is what makes it deployable on the free tier of
# anything.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY . .
# CGO off: this module has no cgo and no third-party dependencies, so the result
# is a static binary. That is the difference between "copy it to the box" and
# "match the libc on the box".
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/rendezvous ./cmd/rendezvous

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/rendezvous /usr/local/bin/rendezvous

# TCP for control and relayed frames; UDP here and one above for behaviour
# probes. The second UDP port is not optional: without it every member is
# measured as restrictive, and that failure does not look like a failure.
EXPOSE 443/tcp 443/udp 444/udp

# Binding 443 as a non-root user needs CAP_NET_BIND_SERVICE from the runtime;
# run with a higher port instead if that is inconvenient.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/rendezvous"]
CMD ["-addr", ":443"]
