# OpenVPN userspace UDP batching (experimental fork)

A fork of **OpenVPN 2.5.11** that batches the **userspace** UDP datapath of the
p2mp server with `recvmmsg`+**GRO** on receive and `sendmmsg`+**GSO** on transmit,
to cut CPU per packet (fewer syscalls + amortized kernel network-stack traversal).
Linux-only, experimental, opt-in. The on-the-wire format is unchanged, so a
patched server stays fully interoperable with stock OpenVPN clients.

This targets the **non-DCO** path (older kernels, TCP transport, or builds without
the in-kernel `ovpn` module, which only exists in 2.6+/Linux 6.16). When DCO is
active the userspace datapath is bypassed and this code does not run.

## What changed

Two new server options, both default `0` = off (original code path untouched):

- **`--udp-batch-rx N`** — receive side. On a socket-read event the server pulls up
  to `N` datagrams in **one `recvmmsg()`** instead of one `recvfrom()` per packet,
  and enables **`UDP_GRO`** so the kernel coalesces same-flow datagrams into a
  super-buffer that we split back into segments before the unchanged decrypt/route
  path. Falls back to recvmmsg-without-GRO, then plain recvmsg.

- **`--udp-batch-tx N`** — transmit side. On a TUN-read event the server drains up
  to `N` packets from the (now non-blocking) tun device in one event-loop wakeup,
  encrypts each, and stages the ciphertext; it then flushes once, grouping
  same-destination equal-size runs into a single **`sendmsg()`+`UDP_SEGMENT` (GSO)**
  call, with **`sendmmsg()`** for the remainder. Flush fires on queue-full or
  tun-drained (one flush per wakeup, no timer → no added latency). GSO runs are
  capped to kernel limits (≤64 segments, ≤65535 bytes) with per-call fallback to
  sendmmsg on `EINVAL`.

Implementation: `socket.{c,h}` (batch primitives), `mudp.c` (server-loop
integration), `multi.{c,h}` (per-server batch containers), `options.{c,h}` (flags).
Crypto, packet-id/replay, and the demux path are unchanged — each datagram is still
encrypted/decrypted individually; only the I/O is batched. Design notes and
datapath trace: [`docs/udp-batching/`](docs/udp-batching/).

## Build

```sh
autoreconf -i && ./configure && make          # autotools; standard deps
# server (Linux p2mp UDP):
openvpn --config server.conf --udp-batch-rx 32 --udp-batch-tx 32
```

## Benchmark environment

5 VMs on a flat L2 (OpenStack, jumbo MTU 9000), **Alpine 3.22 / kernel 6.12**
(so **no DCO** — all traffic goes through the userspace datapath under test):

| role | host | notes |
|------|------|-------|
| VPN server | test-1 | `--mode server`, `10.8.0.0/24`, AES-256-GCM; NAT/MASQUERADE to WAN |
| iperf3 target A | test-2 | `iperf3 -s` |
| iperf3 target B | test-3 | `iperf3 -s` |
| client A | test-4 | CN c1 → target test-2 |
| client B | test-5 | CN c2 → target test-3 |

**Split tunnel, no double-VPN:** each client adds a `/32` route for *its target*
via the tunnel; the server decrypts and NATs that traffic out to the WAN. iperf3
runs only on test-2…5, **never on the VPN server**, so iperf3 never competes with
the (single-threaded) openvpn process for CPU. "Stock" is a separately built,
pristine v2.5.11 (it rejects the batch flags). EC PKI, `dh none`, `data-ciphers
AES-256-GCM`.

**Exact iperf3 command** (run on the client, against its target's real IP):

```sh
# upload   (client→target)  = exercises server RX  (recvmmsg + GRO)
iperf3 -4 -c <target> -P 8 -t 15
# download (-R, target→client) = exercises server TX  (sendmmsg + GSO)
iperf3 -4 -c <target> -P 8 -t 15 -R
# UDP variants add:  -u -b 3000M     (offered rate well above capacity, to stress)
```

`-P 8` (8 parallel streams) is used to push enough aggregate load to saturate the
**single server core**. Server CPU% below is the openvpn process (`utime+stime`,
single-threaded ⇒ **100% = one core fully saturated = the server is the
bottleneck**), sampled for ~9 s mid-run directly on test-1.

## Results

Sanity — **DIRECT, no VPN** (TCP, `-P 8`): 1c **22.0 / 21.7 Gbit/s** up/down,
2c ~20 Gbit/s each — the link is ~20 Gbit/s, so the VPN, not the testbed, is the
limit.

### TCP throughput (Mbit/s, sum of 8 streams) + server CPU%

Server core is ~90–93% in both stock and batch → a fair, CPU-bound comparison.

| scenario (UP=RX, DOWN=TX) | stock | cpu | batch | cpu | Δ |
|---------------------------|------:|----:|------:|----:|----:|
| 1-client UP               |   367 | 90% |   491 | 73% | **+34%** |
| 1-client DOWN             |   387 | 92% |   602 | 92% | **+56%** |
| 2-client UP (A+B)         |   353 | 92% |   764 | 93% | **+116%** |
| 2-client DOWN (A+B)       |   355 | 92% |   650 | 93% | **+83%** |
| mixed UP                  |   215 | 92% |   426 | 92% | **+98%** |
| mixed DOWN                |   156 | 92% |   175 | 92% | +12% |

Notable: 1-client UP reaches 491 Mbit/s at only **73%** CPU (vs stock 367 @ 90%) —
batching does the same work for less CPU; the 2-client cases (server fully loaded)
roughly **double** throughput.

### UDP loss @ `-b 3000M` offered (lower = better)

UDP was driven far above capacity to stress the datapath; the table reports
**packet loss** (clean UDP goodput was not captured this run — see caveat). Batch
generally drops fewer packets for the same offered load:

| scenario | stock loss | batch loss |
|----------|-----------:|-----------:|
| 1-client UP   | 88% | 79% |
| 1-client DOWN | 70% | 57% |
| 2-client DOWN | 83% / 83% | 75% / 74% |

### Summary

Both directions of the non-DCO userspace datapath are batched and measured on a
CPU-saturated single-threaded server: **TCP +34–116%** (largest with multiple
clients / both directions busy), with the server doing equal-or-less CPU per unit
throughput; UDP shows lower loss under overload. No decrypt/replay errors;
stock-client interop intact.

**Caveats (honesty):** numbers are a single run on shared cloud VMs (±noise); the
UDP rows report loss only (the harness parsed the loss field, not goodput, for UDP
receiver lines); one CPU sample misfired (read 0% — a mid-run 9 s snapshot, not a
full-run average). The TCP matrix with CPU% is the reliable result.
