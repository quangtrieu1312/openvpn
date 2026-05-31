/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "multi.h"
#include <inttypes.h>
#include "forward.h"
#include "fdmisc.h"

#include "memdbg.h"

#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

/*
 * Get a client instance based on real address.  If
 * the instance doesn't exist, create it while
 * maintaining real address hash table atomicity.
 */

struct multi_instance *
multi_get_create_instance_udp(struct multi_context *m, bool *floated)
{
    struct gc_arena gc = gc_new();
    struct mroute_addr real;
    struct multi_instance *mi = NULL;
    struct hash *hash = m->hash;

    if (mroute_extract_openvpn_sockaddr(&real, &m->top.c2.from.dest, true)
        && m->top.c2.buf.len > 0)
    {
        struct hash_element *he;
        const uint32_t hv = hash_value(hash, &real);
        struct hash_bucket *bucket = hash_bucket(hash, hv);
        uint8_t *ptr = BPTR(&m->top.c2.buf);
        uint8_t op = ptr[0] >> P_OPCODE_SHIFT;
        bool v2 = (op == P_DATA_V2) && (m->top.c2.buf.len >= (1 + 3));
        bool peer_id_disabled = false;

        /* make sure buffer has enough length to read opcode (1 byte) and peer-id (3 bytes) */
        if (v2)
        {
            uint32_t peer_id = ntohl(*(uint32_t *)ptr) & 0xFFFFFF;
            peer_id_disabled = (peer_id == MAX_PEER_ID);

            if (!peer_id_disabled && (peer_id < m->max_clients) && (m->instances[peer_id]))
            {
                mi = m->instances[peer_id];

                *floated = !link_socket_actual_match(&mi->context.c2.from, &m->top.c2.from);

                if (*floated)
                {
                    /* reset prefix, since here we are not sure peer is the one it claims to be */
                    ungenerate_prefix(mi);
                    msg(D_MULTI_MEDIUM, "Float requested for peer %" PRIu32 " to %s", peer_id,
                        mroute_addr_print(&real, &gc));
                }
            }
        }
        if (!v2 || peer_id_disabled)
        {
            he = hash_lookup_fast(hash, bucket, &real, hv);
            if (he)
            {
                mi = (struct multi_instance *) he->value;
            }
        }
        if (!mi)
        {
            if (!m->top.c2.tls_auth_standalone
                || tls_pre_decrypt_lite(m->top.c2.tls_auth_standalone, &m->top.c2.from, &m->top.c2.buf))
            {
                if (frequency_limit_event_allowed(m->new_connection_limiter))
                {
                    mi = multi_create_instance(m, &real);
                    if (mi)
                    {
                        int i;

                        hash_add_fast(hash, bucket, &mi->real, hv, mi);
                        mi->did_real_hash = true;

                        /* max_clients must be less then max peer-id value */
                        ASSERT(m->max_clients < MAX_PEER_ID);

                        for (i = 0; i < m->max_clients; ++i)
                        {
                            if (!m->instances[i])
                            {
                                mi->context.c2.tls_multi->peer_id = i;
                                m->instances[i] = mi;
                                break;
                            }
                        }

                        /* should not really end up here, since multi_create_instance returns null
                         * if amount of clients exceeds max_clients */
                        ASSERT(i < m->max_clients);
                    }
                }
                else
                {
                    msg(D_MULTI_ERRORS,
                        "MULTI: Connection from %s would exceed new connection frequency limit as controlled by --connect-freq",
                        mroute_addr_print(&real, &gc));
                }
            }
        }

#ifdef ENABLE_DEBUG
        if (check_debug_level(D_MULTI_DEBUG))
        {
            const char *status = mi ? "[ok]" : "[failed]";

            dmsg(D_MULTI_DEBUG, "GET INST BY REAL: %s %s",
                 mroute_addr_print(&real, &gc),
                 status);
        }
#endif
    }

    gc_free(&gc);
    ASSERT(!(mi && mi->halt));
    return mi;
}

/*
 * Send a packet to TCP/UDP socket.
 */
static inline void
multi_process_outgoing_link(struct multi_context *m, const unsigned int mpp_flags)
{
    struct multi_instance *mi = multi_process_outgoing_link_pre(m);
    if (mi)
    {
        multi_process_outgoing_link_dowork(m, mi, mpp_flags);
    }
}

#if defined(TARGET_LINUX)
/*
 * Feed a single received datagram (already placed in m->top.c2.buf with the
 * source address in m->top.c2.from) through the demux + decrypt path, then
 * synchronously flush this instance's deferred output.
 *
 * The flush is required: multi_process_incoming_link() bails out early if
 * m->pending is already set ("if (m->pending) return true;"), so without
 * draining the previous packet's output here the next packet in the batch
 * would be dropped. The drain is bounded because process_outgoing_tun() /
 * process_outgoing_link() always reset their buffers, and multi_process_post()
 * clears m->pending once no output remains (and multi_close_instance() clears
 * it too, so this is safe across a per-instance signal/close).
 */
static void
multi_process_one_packet(struct multi_context *m, const unsigned int mpp_flags)
{
    if (IS_SIG(&m->top))
    {
        return;
    }

    multi_process_incoming_link(m, NULL, mpp_flags);

    while (m->pending && !IS_SIG(&m->top))
    {
        struct context *c = &m->pending->context;
        if (TUN_OUT(c))
        {
            multi_process_outgoing_tun(m, mpp_flags);
        }
        else if (LINK_OUT(c))
        {
            multi_process_outgoing_link(m, mpp_flags);
        }
        else
        {
            break;
        }
    }
}

/*
 * Batched UDP read path (experimental, --udp-batch-rx). Pull up to N datagrams
 * in one recvmmsg() call, optionally split kernel UDP_GRO super-buffers back
 * into segments, and feed each through the unchanged per-packet path. The whole
 * batch is processed within a single io_wait() cycle so the syscall savings are
 * not lost to one epoll_wait() per packet.
 */
static void
multi_process_io_udp_batch(struct multi_context *m, const unsigned int mpp_flags)
{
    struct context *top = &m->top;

    if (!m->udp_batch)
    {
        m->udp_batch = udp_batch_alloc(top->options.udp_batch_rx, &top->c2.frame);
        if (!m->udp_batch)
        {
            /* allocation failed: fall back to a single read for this event */
            read_incoming_link(top);
            if (!IS_SIG(top))
            {
                multi_process_incoming_link(m, NULL, mpp_flags);
            }
            return;
        }
    }

    int k = link_socket_read_udp_posix_recvmmsg(top->c2.link_socket, m->udp_batch);
    if (k <= 0)
    {
        return;
    }

    for (int i = 0; i < k && !IS_SIG(top); ++i)
    {
        struct udp_batch_slot *s = &m->udp_batch->slots[i];

        if (s->buf.len <= 0)
        {
            continue;
        }

        if (s->gso_size > 0 && s->gso_size < s->buf.len)
        {
            /* GRO super-buffer: split into gso_size segments. All segments
             * share one peer/flow, so the source address is the same. */
            const int total = s->buf.len;
            const int seg = s->gso_size;
            for (int off = 0; off < total && !IS_SIG(top); off += seg)
            {
                int this_len = total - off;
                if (this_len > seg)
                {
                    this_len = seg;
                }
                top->c2.buf = s->buf;
                top->c2.buf.offset = s->buf.offset + off;
                top->c2.buf.len = this_len;
                top->c2.from = s->from;
                multi_process_one_packet(m, mpp_flags);
            }
        }
        else
        {
            top->c2.buf = s->buf;
            top->c2.from = s->from;
            multi_process_one_packet(m, mpp_flags);
        }
    }
}

/*
 * Batched UDP TX path (experimental, --udp-batch-tx). On a TUN_READ event, drain
 * several packets from the (now non-blocking) tun device; encrypt + route each
 * through the unchanged per-packet path; capture each resulting outgoing datagram
 * into a TX batch; then flush the batch with one syscall per same-peer run
 * (UDP_SEGMENT GSO + sendmmsg fallback). The tun fd is made non-blocking on first
 * use so the drain loop stops on EAGAIN instead of stalling the event loop.
 *
 * Note (experimental): batched datagrams bypass process_outgoing_link(), so
 * shaper/TOS/link-write byte stats are not applied to them; the caller gates this
 * path off when --shaper is set, and only data packets (not ping/TLS control,
 * which travel via the normal pending path) take it.
 */
static void
multi_process_io_tun_batch(struct multi_context *m, const unsigned int mpp_flags)
{
    struct context *top = &m->top;

    if (!m->udp_tx_batch)
    {
        m->udp_tx_batch = udp_tx_batch_alloc(top->options.udp_batch_tx, &top->c2.frame);
        if (!m->udp_tx_batch || !top->c1.tuntap)
        {
            /* allocation failed: fall back to a single read for this event */
            read_incoming_tun(top);
            if (!IS_SIG(top))
            {
                multi_process_incoming_tun(m, mpp_flags);
            }
            return;
        }
        set_nonblock(top->c1.tuntap->fd);
    }

    struct link_socket *ls = top->c2.link_socket;
    int staged = 0;

    for (int j = 0; j < m->udp_tx_batch->cap && !IS_SIG(top); ++j)
    {
        read_incoming_tun(top);
        if (IS_SIG(top))
        {
            break;
        }
        if (BLEN(&top->c2.buf) <= 0)
        {
            break;      /* tun drained (EAGAIN) */
        }

        multi_process_incoming_tun(m, mpp_flags);

        if (m->pending)
        {
            struct context *c = &m->pending->context;
            if (LINK_OUT(c)
                && link_socket_actual_defined(c->c2.to_link_addr)
                && udp_tx_batch_add(m->udp_tx_batch, &c->c2.to_link, c->c2.to_link_addr))
            {
                c->c2.to_link.len = 0;     /* consumed into the batch */
                staged++;
                multi_set_pending(m, NULL);
            }
            else
            {
                /* batch full, or output is to_tun rather than to_link: leave it
                 * pending for the normal loop and stop draining. */
                break;
            }
        }
    }

    if (staged > 0)
    {
        udp_tx_batch_flush(ls, m->udp_tx_batch);
    }
}
#endif /* TARGET_LINUX */

/*
 * Process an I/O event.
 */
static void
multi_process_io_udp(struct multi_context *m)
{
    const unsigned int status = m->top.c2.event_set_status;
    const unsigned int mpp_flags = m->top.c2.fast_io
                                   ? (MPP_CONDITIONAL_PRE_SELECT | MPP_CLOSE_ON_SIGNAL)
                                   : (MPP_PRE_SELECT | MPP_CLOSE_ON_SIGNAL);

#ifdef MULTI_DEBUG_EVENT_LOOP
    char buf[16];
    buf[0] = 0;
    if (status & SOCKET_READ)
    {
        strcat(buf, "SR/");
    }
    else if (status & SOCKET_WRITE)
    {
        strcat(buf, "SW/");
    }
    else if (status & TUN_READ)
    {
        strcat(buf, "TR/");
    }
    else if (status & TUN_WRITE)
    {
        strcat(buf, "TW/");
    }
#ifdef ENABLE_ASYNC_PUSH
    else if (status & FILE_CLOSED)
    {
        strcat(buf, "FC/");
    }
#endif
    printf("IO %s\n", buf);
#endif /* ifdef MULTI_DEBUG_EVENT_LOOP */

#ifdef ENABLE_MANAGEMENT
    if (status & (MANAGEMENT_READ|MANAGEMENT_WRITE))
    {
        ASSERT(management);
        management_io(management);
    }
#endif

    /* UDP port ready to accept write */
    if (status & SOCKET_WRITE)
    {
        multi_process_outgoing_link(m, mpp_flags);
    }
    /* TUN device ready to accept write */
    else if (status & TUN_WRITE)
    {
        multi_process_outgoing_tun(m, mpp_flags);
    }
    /* Incoming data on UDP port */
    else if (status & SOCKET_READ)
    {
#if defined(TARGET_LINUX)
        if (m->top.options.udp_batch_rx > 0)
        {
            multi_process_io_udp_batch(m, mpp_flags);
        }
        else
#endif
        {
            read_incoming_link(&m->top);
            if (!IS_SIG(&m->top))
            {
                multi_process_incoming_link(m, NULL, mpp_flags);
            }
        }
    }
    /* Incoming data on TUN device */
    else if (status & TUN_READ)
    {
#if defined(TARGET_LINUX)
        if (m->top.options.udp_batch_tx > 0
            && proto_is_udp(m->top.c2.link_socket->info.proto)
            && !m->top.options.shaper)
        {
            multi_process_io_tun_batch(m, mpp_flags);
        }
        else
#endif
        {
            read_incoming_tun(&m->top);
            if (!IS_SIG(&m->top))
            {
                multi_process_incoming_tun(m, mpp_flags);
            }
        }
    }
#ifdef ENABLE_ASYNC_PUSH
    /* INOTIFY callback */
    else if (status & FILE_CLOSED)
    {
        multi_process_file_closed(m, mpp_flags);
    }
#endif
}

/*
 * Return the io_wait() flags appropriate for
 * a point-to-multipoint tunnel.
 */
static inline unsigned int
p2mp_iow_flags(const struct multi_context *m)
{
    unsigned int flags = IOW_WAIT_SIGNAL;
    if (m->pending)
    {
        if (TUN_OUT(&m->pending->context))
        {
            flags |= IOW_TO_TUN;
        }
        if (LINK_OUT(&m->pending->context))
        {
            flags |= IOW_TO_LINK;
        }
    }
    else if (mbuf_defined(m->mbuf))
    {
        flags |= IOW_MBUF;
    }
    else
    {
        flags |= IOW_READ;
    }
#ifdef _WIN32
    if (tuntap_ring_empty(m->top.c1.tuntap))
    {
        flags &= ~IOW_READ_TUN;
    }
#endif
    return flags;
}


/**************************************************************************/
/**
 * Main event loop for OpenVPN in UDP server mode.
 * @ingroup eventloop
 *
 * This function implements OpenVPN's main event loop for UDP server mode.
 *  At this time, OpenVPN does not yet support multithreading.  This
 * function's name is therefore slightly misleading.
 *
 * @param top - Top-level context structure.
 */
static void
tunnel_server_udp_single_threaded(struct context *top)
{
    struct multi_context multi;

    top->mode = CM_TOP;
    context_clear_2(top);

    /* initialize top-tunnel instance */
    init_instance_handle_signals(top, top->es, CC_HARD_USR1_TO_HUP);
    if (IS_SIG(top))
    {
        return;
    }

    /* initialize global multi_context object */
    multi_init(&multi, top, false, MC_SINGLE_THREADED);

    /* initialize our cloned top object */
    multi_top_init(&multi, top);

    /* initialize management interface */
    init_management_callback_multi(&multi);

    /* finished with initialization */
    initialization_sequence_completed(top, ISC_SERVER); /* --mode server --proto udp */

#ifdef ENABLE_ASYNC_PUSH
    multi.top.c2.inotify_fd = inotify_init();
    if (multi.top.c2.inotify_fd < 0)
    {
        msg(D_MULTI_ERRORS | M_ERRNO, "MULTI: inotify_init error");
    }
#endif

    /* per-packet event loop */
    while (true)
    {
        perf_push(PERF_EVENT_LOOP);

        /* set up and do the io_wait() */
        multi_get_timeout(&multi, &multi.top.c2.timeval);
        io_wait(&multi.top, p2mp_iow_flags(&multi));
        MULTI_CHECK_SIG(&multi);

        /* check on status of coarse timers */
        multi_process_per_second_timers(&multi);

        /* timeout? */
        if (multi.top.c2.event_set_status == ES_TIMEOUT)
        {
            multi_process_timeout(&multi, MPP_PRE_SELECT|MPP_CLOSE_ON_SIGNAL);
        }
        else
        {
            /* process I/O */
            multi_process_io_udp(&multi);
            MULTI_CHECK_SIG(&multi);
        }

        perf_pop();
    }

#ifdef ENABLE_ASYNC_PUSH
    close(top->c2.inotify_fd);
#endif

    /* shut down management interface */
    uninit_management_callback();

    /* save ifconfig-pool */
    multi_ifconfig_pool_persist(&multi, true);

    /* tear down tunnel instance (unless --persist-tun) */
    multi_uninit(&multi);
    multi_top_free(&multi);
    close_instance(top);
}

void
tunnel_server_udp(struct context *top)
{
    tunnel_server_udp_single_threaded(top);
}

