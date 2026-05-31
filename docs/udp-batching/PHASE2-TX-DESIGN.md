# Phase 2 design — TX batching (sendmmsg + UDP_SEGMENT/GSO), 2.5.11

## TX datapath today (verified)
- p2mp UDP server writes **exactly one datagram per event-loop iteration**:
  `mudp.c multi_process_outgoing_link` → `multi.h multi_process_outgoing_link_dowork`
  → `forward.c process_outgoing_link()` (L1605) → `socket.h link_socket_write()` (L1208)
  → `link_socket_write_udp_posix()` (L1167) → `sendto()` (L1179) **or**
  `link_socket_write_udp_posix_sendmsg()` (`socket.c` L3706, `sendmsg`+IP_PKTINFO cmsg).
- Download direction (server→client, i.e. the iperf3 *download* case): the TUN read
  branch `read_incoming_tun()` reads **one** tun packet → `multi_process_incoming_tun()`
  demuxes to the destination instance, encrypts, sets `c2.to_link`; the next loop
  iteration writes that single datagram.

## The core problem
RX batching was natural — the kernel *hands us* a batch via `recvmmsg`/GRO. TX is the
opposite: the app must **accumulate** several outgoing datagrams before one syscall.
OpenVPN 2.x has **no accumulation point** — every packet is encrypted and written
immediately, one per loop iteration. So TX batching is materially more invasive than RX.

Two kernel mechanisms, two requirements:
- **`sendmmsg`** — N datagrams, possibly N different destinations, one syscall. Needs a
  staged vector of ready-to-send datagrams.
- **`UDP_SEGMENT` (GSO)** — one `sendmsg` carrying a super-buffer the kernel slices into
  equal-size segments; **all segments must be same destination and (except the last)
  same size**. Needs ≥2 queued datagrams to the *same peer*.

## Options

### (A) TUN-ingest batch + per-peer GSO flush  *(the real download win)*
Read many tun packets per wakeup (loop `read_incoming_tun` or tun `recvmmsg`), encrypt
each, **bucket the resulting records by destination peer**; for each peer with a run of
equal-size records emit one `sendmsg`+`UDP_SEGMENT`, remainder via `sendmmsg`.
- Pro: this is where throughput actually improves (server→many-clients, big streams).
- Con: significant change to the TUN ingest loop, a new per-peer TX staging area, and
  care around encrypt/packet-id ordering and the existing single-`to_link` model. Biggest
  blast radius of anything in this experiment.

### (B) Flush-side sendmmsg only (no GSO)
Keep per-packet encryption but, instead of writing each `to_link` immediately, stage it
and `sendmmsg` a small vector when the loop has several ready (e.g. mbuf/broadcast drain,
or a short coalescing window).
- Pro: smaller change, no GSO equal-size constraint.
- Con: smaller win; the server rarely has many datagrams ready at once without (A).

### (C) mbuf/broadcast-only GSO
Only batch the broadcast/client-to-client path. Tiny blast radius, negligible real-world
benefit. Not recommended.

## Recommendation
(A) is the only option that yields a download-side throughput win comparable to Phase 1's
RX win, but it is the largest and riskiest change in this experiment and effectively also
batches the TUN read side. (B) is a safe incremental step. Decide scope before coding.

## Implemented (A)+(B): flush semantics
Chosen design — `--udp-batch-tx N` (0 = off):

On a `TUN_READ` event the server drains up to `N` packets from the **non-blocking**
tun fd in one event-loop wakeup; each is demuxed + encrypted by the unchanged
`multi_process_incoming_tun()`, and the resulting ciphertext datagram is copied
into a per-`multi_context` TX arena (`udp_tx_batch_add`). The batch is flushed
**when the queue is full (N reached) OR the tun drains (EAGAIN)** — i.e. once per
wakeup. There is deliberately **no time-based accumulator/timer**: holding packets
across wakeups would add latency for marginal gain, and the event loop already
provides a natural batching boundary (this matches wireguard-go / quiche, which
batch what is readily available per wakeup rather than waiting on a timer).

`udp_tx_batch_flush` groups the staged datagrams into same-destination,
equal-size runs and sends each run as one `sendmsg`+`UDP_SEGMENT` (GSO);
leftover/unequal/single datagrams go via `sendmmsg`. GSO runs are capped to the
kernel limits: **≤ 64 segments (`UDP_MAX_SEGMENTS`) and ≤ 65535 bytes total** per
send (so at a ~1500 B MTU a GSO send carries ≤ ~43 segments). On any GSO
`sendmsg` error (e.g. `EINVAL`) the code disables GSO and falls back to sendmmsg.

Reference values for the cap: wireguard-go uses `IdealBatchSize = 128`; the
kernel hard limit is `UDP_MAX_SEGMENTS = 64`. Recommended `--udp-batch-tx`: 32–64.

Scope note: batched datagrams bypass `process_outgoing_link()`, so shaper/TOS and
per-link byte stats are not applied to them — the path is gated off when
`--shaper` is set, and only the p2mp UDP server data path uses it. Broadcast /
client-to-client packets (no single destination) are left to the normal mbuf
path. Linux-only; non-Linux and `--udp-batch-tx 0` keep the original one-write
path untouched.

## Constraints / gotchas
- `UDP_SEGMENT` gso_size is set via a `SOL_UDP`/`UDP_SEGMENT` cmsg (int = segment size).
- Mixed-size tails: only the final segment may differ in size → bucket equal-size runs.
- IP_PKTINFO (multihome) + GSO cmsgs coexist in one `msg_control`.
- Per-peer crypto state (packet-id, IV) must still advance per logical datagram → must
  encrypt each record individually *before* coalescing the ciphertext for GSO.
- Linux-only, gated behind a new `--udp-batch-tx N` (0 = off), same as Phase 1.
