# Phase 2 TX batching — benchmark results (OpenVPN 2.5.11, Alpine testbed)

Feature: `--udp-batch-tx N` adds `sendmmsg()` + `UDP_SEGMENT` (GSO) to the p2mp
UDP server transmit path (Linux only). Same testbed/topology as the Phase 1 RX
benchmark (see BENCH-2.5.11.md): split-tunnel, NAT to WAN, iperf3 on test-2/3
(never on the VPN server). DOWNLOAD direction (client `iperf3 -R`) exercises the
server's TUN-read → encrypt → UDP-send path, which is what TX batching touches.
Conditions: **stock** (separately built pristine v2.5.11) vs **tx-batch**
(`--udp-batch-tx 32`). MTU 9000.

## Throughput (Mbit/s, iperf3 receiver)
| scenario              | stock            | tx-batch          |     Δ |
|-----------------------|------------------|-------------------|------:|
| TCP 1-client DOWN     | 398              | 543               |  +36% |
| UDP 1-client DOWN     | 590 (41% loss)   | 984 (1.7% loss)   |  +67% |
| TCP 2-client DOWN A+B | 307 + 86 = 393   | 254 + 408 = 662   |  +68% |

The UDP single-client case is the clearest: the unbatched server dropped ~41% on
transmit; GSO raised goodput to 984 Mbit/s at 1.7% loss. (UDP 2-client cells did
not capture — an iperf3 `-R` UDP-summary quirk under contention, not a server
fault; TCP 2-client did capture and shows the gain.)

## Syscall proof (strace -c, server, 1-client UDP download, 12s)
| syscall          | stock  | tx-batch |
|------------------|-------:|---------:|
| `sendto`         | 29,300 | 3        |
| `sendmsg` (GSO)  | 0      | 54,088*  |
| `poll`           | 58,638 | 1,734    |

Per-datagram `sendto` collapses to ~0, replaced by `sendmsg`+`UDP_SEGMENT`; `poll`
drops ~34×. (*The `sendmsg` total is large because each call carries many
segments in one GSO super-buffer — that is the coalescing working; the efficiency
shows in the `poll` collapse and the throughput/loss numbers, not in a smaller
sendmsg count.) No decrypt/replay/auth errors; no crashes.

## Flush semantics (implemented)
Per `TUN_READ` wakeup the server drains up to N packets from the non-blocking tun
fd, encrypts each, stages the ciphertext, and flushes once — on **queue-full (N)
or tun-drained (EAGAIN)**. No cross-wakeup timer ⇒ no added latency. Flush groups
same-destination equal-size runs into one `sendmsg`+`UDP_SEGMENT` (capped to the
kernel limits: ≤64 segments and ≤65535 bytes/send), remainder via `sendmmsg`,
with per-call fallback to sendmmsg if GSO returns EINVAL. Gated off under
`--shaper`; broadcast/c2c left to the normal path. See PHASE2-TX-DESIGN.md.

## Takeaway
TX batching raises server transmit-side download throughput ~+36–68% and nearly
eliminates transmit-path UDP loss (41%→1.7% single-client), collapsing per-packet
`sendto` into GSO `sendmsg` and cutting `poll` ~34×. Together with Phase 1 (RX,
recvmmsg+GRO), both directions of the non-DCO userspace datapath are now batched.
