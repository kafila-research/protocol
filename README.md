# Kafila protocol

How the machines in a Kafila session find each other and talk, when none of them
can be dialled from outside.

Three pieces, and nothing else:

| | |
|---|---|
| [`rendezvous`](rendezvous) | a service both parties reach *outbound*, which introduces them and relays between them until they can do better |
| [`reach`](reach) | what a machine's network does to outbound UDP, which is what decides whether a pair can find a direct path |
| [`cmd/rendezvous`](cmd/rendezvous) | the service as a standalone binary |

## Why this is its own repository

Kafila splits a model across consumer machines. Those machines need a GPU, a
model, and a large native toolchain. The rendezvous needs none of that — it
holds no model, runs no inference, and sees no prompt. Its entire job is to
introduce two machines and copy bytes between them.

The machine that should run one is the opposite kind of machine: always-on,
cheap, and somewhere both parties can reach. A free-tier cloud instance with a
gigabyte of memory and no GPU. Asking that host to build a GPU stack it will
never call is not reasonable, and neither is asking it to clone an inference
engine to get a program that copies sockets.

So this depends on nothing. No third-party modules, no cgo, no native
libraries. It builds with `CGO_ENABLED=0` into a **4 MB static binary** that
runs on any Linux, with no glibc version to match between the machine that
built it and the machine that runs it.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" ./cmd/rendezvous
```

Kafila imports this module. Nothing here imports Kafila.

## Running a rendezvous

```sh
rendezvous -addr :443
```

That is the whole thing. It needs no model, no GPU, and no configuration.

**Use 443 if the machine has nothing else on it.** Corporate networks, hotels
and some mobile carriers block arbitrary ports and almost never block that one.
It costs nothing to choose and removes a class of failure that is tedious to
diagnose from the far end.

### What it needs open

| | |
|---|---|
| TCP, one port | session control, and the relayed frames |
| UDP, the same port **and the one above** | behaviour probes |
| bandwidth | while paths are relayed, every hidden state passes through here |

**The second UDP port is the one people forget**, and its absence does not look
like an error — it looks like every member having a restrictive network.

The probe answers from a second port on purpose. That is the only way to find
out whether a member's network will accept a packet from an address it has not
written to, which is the property that decides whether the hard pairings can be
direct (RFC 5780). If that port is blocked *at the server*, every member is
classified restrictive and the measurement is quietly, uniformly wrong.

### As a service

```ini
[Unit]
Description=Kafila rendezvous
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/rendezvous -addr :443
Restart=always
RestartSec=2

# An unprivileged transient user, plus the one capability needed to bind 443.
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# It copies bytes between sockets; it has no reason to touch the filesystem.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

### Checking it before trusting it

From any machine that is not the server, ask to join a session that does not
exist:

```sh
ollama runner --session --rendezvous <server>:443 --code nosuchcode
```

A clean "no session with that code" means TCP is reaching the service. If it
hangs or refuses, the port is blocked or nothing is listening.

The UDP side shows up in the host's log when a session starts: each member is
reported with a class. If **every** member reads `restrictive` or `unknown`,
suspect the server's second UDP port before believing it about the members'
networks.

## What the operator can see

While paths are relayed, hidden states pass through this machine. A hidden
state is not opaque — it carries a great deal about the text that produced it —
so a rendezvous is not a neutral pipe in the way a DNS server is. Run it
somewhere you would be comfortable running the model itself.

Moving paths off the relay is the next piece of work, and it is the reason that
work matters beyond speed.

## Licence

Dual-licensed, on the same terms as Kafila: [PolyForm Noncommercial
1.0.0](LICENSE.md) for research, teaching, and personal use, or a commercial
licence. See [LICENSING.md](LICENSING.md).
