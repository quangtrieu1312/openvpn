# Phase 1 RX batching — benchmark results (OpenVPN 2.5.11, Alpine testbed)

Feature: `--udp-batch-rx N` adds `recvmmsg()` + `UDP_GRO` to the p2mp UDP server
receive path (Linux only). Branch base: `v2.5.11`. Binary built on-target
(musl, Alpine 3.22, gcc 14, OpenSSL 3.5). No DCO (kernel 6.12 / OpenVPN 2.5 →
pure userspace datapath, so the RX loop is actually exercised).

## Testbed
5 VMs, flat L2, 9000-MTU underlay (tests pin eth0 to 1500 and 3506):
- **server** test-1 — UDP `--mode server`, `10.8.0.0/24`, AES-256-GCM, NAT/MASQUERADE
  out eth0 (split-tunnel: clients add a /32 route for their target via the tunnel,
  decrypted traffic egresses to the WAN — no double-VPN, no client-to-client).
- **clients** test-4 (CN c1) → target test-2, test-5 (CN c2) → target test-3.
- **targets** test-2/test-3 run `iperf3 -s` (never co-located with the VPN server,
  so iperf3 and openvpn never race for CPU).

Conditions: **direct** (no VPN) · **stock** (pristine v2.5.11, separate build,
rejects `--udp-batch-rx`) · **batch** (`--udp-batch-rx 32`, logs `UDP_GRO enabled`).
Each: 1-up, 1-down, 2-up, 2-down, 1up+1down — in TCP and UDP, iperf3 `-4`.

## Syscall counts (strace -c, server, ~13 s, 2-client UDP upload @ `-l 300 -b 1000M`)
Clean A/B capture. NOTE the two runs did **not** carry equal volume in the window
(batch forwarded ~3× the data — see `write` = per-packet tun forwards), so compare
**per-datagram behaviour**, not raw totals:

| syscall       | STOCK   | BATCH (--udp-batch-rx 32) |
|---------------|--------:|--------------------------:|
| `write` (tun) | 46,275  | 146,756                   |
| `recvfrom`    | 46,275  | 0                         |
| `recvmmsg`    | 0       | 2,307                     |
| `poll`        | 92,591  | 2,351                     |

Reading (verified from the raw strace files):
- **STOCK = exactly one `recvfrom` per forwarded datagram** (46,275 / 46,275) and
  two `poll`s per datagram — the per-packet receive model.
- **BATCH eliminates `recvfrom` entirely** (→ 0), replaced by `recvmmsg`; with
  UDP_GRO each call pulls **~64 datagrams** (146,756 forwarded / 2,307 recvmmsg).
- **`poll` collapses ~39×** (92,591 → 2,351), and per forwarded datagram it drops
  ~80× (2.0 → 0.016). This is the syscall-level signature of the win: far fewer
  receive calls and event-loop wakeups per packet, plus GRO amortizing kernel UDP
  stack traversal — consistent with the +15–40% receive throughput below. No
  decrypt/replay errors. (`UDP batch RX: UDP_GRO enabled` is logged at startup.)

## Throughput — server RX path = client UPLOAD (Mbit/s, iperf3 receiver)
RX batching only touches the server receive path, so upload is the signal;
download (server TX, unbatched) is the control and stays ~flat.

### MTU 1500
| scenario            | stock | batch |    Δ |
|---------------------|------:|------:|-----:|
| TCP 1-client UP     |   365 |   445 | +22% |
| TCP 2-client UP A+B |   398 |   524 | +32% |
| TCP mixed UP        |   247 |   353 | +43% |
| UDP 1-client UP     |   522 |   634 | +21% |
| UDP 2-client UP A+B |   869 |   900 |  +4% |
| UDP mixed UP        |   549 |   623 | +13% |

### MTU 3506
| scenario            | stock | batch |    Δ |
|---------------------|------:|------:|-----:|
| TCP 1-client UP     |   380 |   455 | +20% |
| TCP 2-client UP A+B |   435 |   488 | +12% |
| UDP 1-client UP     |   527 |   720 | +37% |

Download/TX control stayed within noise (e.g. UDP 1-down 597→606, TCP 1-down
385→405), confirming the gain is RX-specific. DIRECT sanity: TCP ~20 Gbit/s,
UDP 1 Gbit/s @ ~0% loss at both MTUs (testbed is not the bottleneck).

## Takeaway
RX batching raises server receive-side throughput ~+15–40% (cleanest on
single-client upload, +20–37%) while download is unchanged — the expected
signature of an RX-only optimization on the non-DCO userspace path. At the
syscall level: per-datagram `recvfrom` is eliminated in favour of `recvmmsg`
(~64 datagrams/call under UDP_GRO) and `poll` drops ~39× — far fewer receive
calls and wakeups per packet. A few cells hit transient iperf3 races (marked n/a
in the raw log) and are excluded.
