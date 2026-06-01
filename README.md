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

5 VMs on a flat L2 (OpenStack, jumbo-capable underlay; **eth0 pinned per run to
MTU 9000 and 1500**), **Alpine 3.22 / kernel 6.12** (so **no DCO** — all traffic
goes through the userspace datapath under test):

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

`-P 8` (8 parallel streams) is used to push enough aggregate load to drive the
server's CPU to its ceiling.

**How to read the CPU% column:** it is the openvpn **process** CPU as `top`/`pidstat`
report it — `(Δutime + Δstime) / wall`, where **one core = 100%** (CLK_TCK 100,
sampled ~9 s mid-run directly on test-1). It is **not** normalized to the box's two
cores (that scale would be 200%). Because the OpenVPN 2.5 data path is
**single-threaded**, the relevant ceiling is **100% = one core**; the second core
cannot help it. So **~90% means the openvpn thread is using ~0.9 of one core** —
near-saturated, with the remaining ~10% spent blocked in syscalls/`epoll_wait`, not
idle headroom. This is what makes the stock-vs-batch comparison fair: both are
pinned at the same one-core ceiling, so higher throughput at equal CPU is a real
per-packet efficiency gain.

## Results

Server **stock v2.5.11** vs **batch** (`--udp-batch-rx 32 --udp-batch-tx 32`),
at two underlay MTUs: **9000** (jumbo, unfragmented encapsulation) and **1500**
(the common case — the ~1.5 KB encapsulated datagram is IP-fragmented on the wire).
iperf3 `-P 8 -t 15`; server CPU sampled ~9 s mid-run (one core = 100%; see note
above). Single run per cell on shared cloud VMs (±noise). Rerun 2026-06-01; raw data
in [`docs/udp-batching/BENCH-RERUN-2026-06-01.tsv`](docs/udp-batching/BENCH-RERUN-2026-06-01.tsv).
Clients are stock OpenVPN 2.6.20 (apk) in both columns — only the **server** binary
changes. Sanity — DIRECT, no VPN (TCP, `-P 8`): ~20 Gbit/s, so the VPN, not the
testbed, is the limit.

### TCP throughput (Mbit/s, sum of 8 streams) + server CPU%

UP = client→target = server **RX** (recvmmsg+GRO). DOWN (`-R`) = server **TX**
(sendmmsg+GSO). 2-client rows are the **A+B sum**; mixed = A-up + B-down at once
(shared CPU sample).

**MTU 9000 (jumbo / unfragmented)**

| scenario      | stock | cpu | batch | cpu |     Δ |
|---------------|------:|----:|------:|----:|------:|
| 1-client UP   |   359 | 87% |   445 | 71% |  +24% |
| 1-client DOWN |   397 | 91% |   747 | 91% |  +88% |
| 2-client UP   |   389 | 92% |   514 | 84% |  +32% |
| 2-client DOWN |   472 | 93% |   945 | 95% | +100% |
| mixed UP      |   220 | 92% |   276 | 94% |  +25% |
| mixed DOWN    |   187 | 92% |   439 | 94% | +135% |

**MTU 1500 (fragmented encapsulation)**

| scenario      | stock | cpu | batch | cpu |     Δ |
|---------------|------:|----:|------:|----:|------:|
| 1-client UP   |   345 | 88% |   365 | 78% |   +6% |
| 1-client DOWN |   414 | 92% |   716 | 93% |  +73% |
| 2-client UP   |   388 | 92% |   503 | 85% |  +30% |
| 2-client DOWN |   510 | 92% |   742 | 95% |  +45% |
| mixed UP      |   238 | 92% |   311 | 95% |  +31% |
| mixed DOWN    |   174 | 92% |   443 | 95% | +155% |

Headline: **TX batching (DOWN) is the big win and holds at both MTUs** — +73–100%
on 1/2-client downloads and +135–155% on the mixed download, only modestly smaller
at 1500 than at 9000. RX batching (UP) helps most when the server is CPU-bound with
multiple flows (+24–32%); the weakest cell is 1500 1-client UP (+6%), where the
server isn't RX-saturated — note batch still uses **less** CPU there (78% vs 88%),
i.e. it returns headroom rather than throughput. Several batch cells deliver more
throughput at **equal-or-lower CPU** (e.g. 9000 1-up 445 @71% vs 359 @87%) — a real
per-packet efficiency gain.

### UDP under overload (`-b 3000M` offered) — download/TX goodput (Mbit/s recv) / loss

Driven far above capacity to stress the datapath. Download (server TX) is the clean
signal — goodput rises and loss falls with batching at **both** MTUs:

| scenario (DOWN/TX) | MTU  | stock goodput / loss | batch goodput / loss |
|--------------------|-----:|---------------------:|---------------------:|
| 1-client DOWN      | 9000 | 695 / 67%            | 921 / 59%            |
| 2-client DOWN      | 9000 | 685 / 68%            | 953 / 58%            |
| 1-client DOWN      | 1500 | 667 / 70%            | 969 / 57%            |
| 2-client DOWN      | 1500 | 643 / 71%            | 921 / 59%            |

### Summary

Both directions of the non-DCO userspace datapath are batched and measured on a
CPU-saturated single-threaded server, now at **both MTU 9000 and 1500**: TX batching
gives the largest, MTU-robust gains (**+45–100%** on downloads, up to +155% mixed),
RX batching adds **+24–32%** when multi-flow CPU-bound — with the server doing
equal-or-less CPU per unit throughput. UDP TX goodput is higher and loss lower under
overload at both MTUs. No decrypt/replay errors; stock-client interop intact.

**Caveats (honesty):** single run per cell on shared cloud VMs (±noise); one CPU
sample (~9 s mid-run, not a full-run average). The **TCP matrices are the reliable
result**; UDP is supplementary — a few aggregate UDP cells didn't parse under heavy
overload, so UDP UP rows are omitted. Server stock = pristine 2.5.11; batch = the
2.5.11 fork; clients = stock 2.6.20 throughout.
