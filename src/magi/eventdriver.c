/*
 * EVER/IP(R)
 * Copyright (c) 2017 kristopher tate & connectFree Corporation.
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This project may be licensed under the terms of the GNU AFFERO General
 * Public License version 3. Corporate and Academic licensing terms are also
 * available. Contact <licensing@connectfree.co.jp> for details.
 *
 * connectFree, the connectFree logo, and EVER/IP are registered trademarks
 * of connectFree Corporation in Japan and other countries. connectFree
 * trademarks and branding may not be used without express writen permission
 * of connectFree. Please remove all trademarks and branding before use.
 *
 * See the LICENSE file at the root of this project for complete information.
 *
 */

#include <re.h>
#include <everip.h>

#define PING_MAGIC 0x01234567

struct magi_eventdriver_handler {
	struct csock *csock; /* keep on top? */
	struct le le;
};

struct _starfinder {
    struct csock csock;
    struct le le;
    uint16_t id;

    struct magi_eventdriver *ctx;

    uint32_t superiority;
    uint32_t version;

    #define STARFINDER_STATE_DISCONNECTED 0
    #define STARFINDER_STATE_CONNECTED    1
    #define STARFINDER_STATE_ERROR        2
    uint16_t state;

    uint32_t bytes_accumulated;
};

static bool EVD_STAR_CHECKSIZE(enum EVD_STAR ep, size_t s)
{
    switch (ep) {
        case EVD_STAR_CONNECT:
            return (s == 8 + 72);
        case EVD_STAR_SUPERIORITY:
            return (s == 8 + 4);
        case EVD_STAR_NODE:
            return (s == 8 + 64);
        case EVD_STAR_SENDMSG:
            return (s >= 8 + 72);
        case EVD_STAR_PING:
        case EVD_STAR_PONG:
            return (s >= 8 + 8);
        case EVD_STAR_SESSIONS:
        case EVD_STAR_PEERS:
        case EVD_STAR_PATHFINDERS:
            return (s == 8);
        default:;
    }
    error("invalid event [%d]", ep);
    ASSERT_TRUE(0);
    return false;
}

ASSERT_COMPILETIME(EVD_STAR__TOO_LOW == 511);
ASSERT_COMPILETIME(EVD_STAR__TOO_HIGH == 521);

static bool EVD_CORE_CHECKSIZE(enum EVD_CORE ep, size_t s)
{
    switch (ep) {
        case EVD_CORE_CONNECT:
            return (s == 8 + 40);
        case EVD_CORE_PATHFINDER:
        case EVD_CORE_PATHFINDER_GONE:
            return (s == 8 + 72);
        case EVD_CORE_SWITCH_ERR:
            return (s >= 8 + 40);
        case EVD_CORE_SEARCH_REQ:
            return (s == 8 + 16);
        case EVD_CORE_PEER:
        case EVD_CORE_PEER_GONE:
        case EVD_CORE_SESSION:
        case EVD_CORE_SESSION_ENDED:
        case EVD_CORE_DISCOVERED_PATH:
            return (s == 8 + 64);
        case EVD_CORE_MSG:
            return (s >= 8 + 72);
        case EVD_CORE_PING:
        case EVD_CORE_PONG:
            return (s == 8 + 8);
        default:;
    }
    error("invalid event [%d]", ep);
    ASSERT_TRUE(0);
    return false;
}

ASSERT_COMPILETIME(EVD_CORE__TOO_LOW == 1023);
ASSERT_COMPILETIME(EVD_CORE__TOO_HIGH == 1037);

static struct csock *_send_tosf(struct _starfinder *sf, struct mbuf *mb );

static struct list* _handlers_get( struct magi_eventdriver *eventd
                                 , enum EVD_STAR es )
{
	#define OFF(es) (es - EVD_STAR__TOO_LOW - 1)
    if (es <= EVD_STAR__TOO_LOW || es >= EVD_STAR__TOO_HIGH) {
    	return NULL;
    }
    return &eventd->csocks[OFF(es)];
    #undef OFF
}

static struct csock *_incoming_sf( struct csock *csock
                                 , struct mbuf *mb )
{
    if (!csock || !mb)
        return NULL;

    struct _starfinder *sf = container_of(csock, struct _starfinder, csock);
    struct magi_eventdriver *ed = sf->ctx;

    debug("_incoming_sf\n");

    if (mbuf_get_left(mb) < 4) {
        debug("SF:DROP runt\n");
        return NULL;
    }

    enum EVD_STAR es = mbuf_read_u32(mb);
    mbuf_advance(mb, -8);
    mbuf_write_u32(mb, es);
    mbuf_write_u32(mb, sf->id);
    mbuf_advance(mb, -8);

    if (es <= EVD_STAR__TOO_LOW || es >= EVD_STAR__TOO_HIGH) {
        debug("SF:DROP invalid type [%d]", es);
        return NULL;
    }
    if (!EVD_STAR_CHECKSIZE(es, mbuf_get_left(mb))) {
        debug("SF:DROP incorrect length[%d] for type [%d]", mbuf_get_left(mb), es);
        return NULL;
    }

    if (sf->state == STARFINDER_STATE_DISCONNECTED) {
        if (es != EVD_STAR_CONNECT) {
            debug("SF:DROP disconnected and event != CONNECT event:[%d]", es);
            return NULL;
        }
    } else if (sf->state != STARFINDER_STATE_CONNECTED) {
        debug("SF:DROP error state");
        return NULL;
    }

    switch (es) {
        default: goto handlers;

        case EVD_STAR_CONNECT: {
            debug("EVD_STAR_CONNECT\n");
            mbuf_advance(mb, 8);

            sf->superiority = arch_betoh32(mbuf_read_u32(mb));
            sf->version = arch_betoh32(mbuf_read_u32(mb));
            sf->state = STARFINDER_STATE_CONNECTED;

            ASSERT_TRUE(sf->version == EVERIP_VERSION_PROTOCOL);

            mbuf_advance(mb, -44);

            mbuf_write_u32(mb, EVD_CORE_CONNECT);
            mbuf_write_u32(mb, arch_betoh32(EVERIP_VERSION_PROTOCOL));
            mbuf_write_u32(mb, arch_betoh32(sf->id));
            mbuf_write_mem(mb, ed->pubkey, 32);

            mbuf_advance(mb, -44);

            struct mbuf *mb_clone = mbuf_clone(mb);
            CSOCK_CALL(_send_tosf, sf, mb_clone);
            mb_clone = mem_deref(mb_clone);

            return NULL;
        }
        case EVD_STAR_SUPERIORITY: {
            debug("EVD_STAR_SUPERIORITY\n");
            return NULL;
        }

        case EVD_STAR_PING: {
            debug("EVD_STAR_PING\n");
            return NULL;
        }
        case EVD_STAR_PONG: {
            debug("EVD_STAR_PONG\n");
            return NULL;
        }
        case EVD_STAR_PATHFINDERS: {
            debug("EVD_STAR_PATHFINDERS\n");
            return NULL;
        }
    }

handlers:

    {
        struct list *handlers = _handlers_get(ed, es);
        if (!handlers) return NULL;
        struct le *le;
        struct magi_eventdriver_handler *edh;
        LIST_FOREACH(handlers, le) {
            edh = le->data;
            struct mbuf *mb_clone = mbuf_clone(mb);
            ASSERT_TRUE(edh->csock);
            ASSERT_TRUE(edh->csock->send);
            CSOCK_CALL(edh->csock->send, edh->csock, mb_clone);
            mb_clone = mem_deref(mb_clone);
        }
    }

    return NULL;
}

static void ed_starfinder_destructor(void *data)
{
    struct _starfinder *sf = data;
    list_unlink(&sf->le);
}

void magi_eventdriver_register_star( struct magi_eventdriver *eventd
                                   , struct csock *csock )
{
    struct _starfinder *sf;

    if (!eventd || !csock) {
        return;
    }

    sf = mem_zalloc(sizeof(*sf), ed_starfinder_destructor);
    if (!sf)
        return;

    sf->csock.send = _incoming_sf;
    csock_flow(&sf->csock, csock);
    sf->id = list_count(&eventd->starfinders);
    sf->ctx = eventd;

    list_append(&eventd->starfinders, &sf->le, sf);

    debug("USING ID = [%u]\n", sf->id);

}

static void ed_handler_destructor(void *data)
{
	struct magi_eventdriver_handler *edh = data;
	list_unlink(&edh->le);
    edh->csock->adj = NULL;
}

void magi_eventdriver_register_core( struct magi_eventdriver *eventd
								   , struct csock *csock
								   , enum EVD_STAR es )
{
	struct magi_eventdriver_handler *ed_handler;
	if (!eventd || !csock) {
		return;
	}

	debug("magi_eventdriver_register_core\n");

	struct list *list = _handlers_get(eventd, es);
	if (!list) {
		debug("could not _handlers_get for [ep=%d]\n", es);
		return;
	}

	ed_handler = mem_zalloc(sizeof(*ed_handler), ed_handler_destructor);
	if (!ed_handler)
		return;

	ed_handler->csock = csock;
	list_append(list, &ed_handler->le, ed_handler);

	csock->adj = &eventd->virtual_cs;

	return;
}

static struct csock *_send_tosf( struct _starfinder *sf
							   , struct mbuf *mb )
{
    if (!sf || sf->state != STARFINDER_STATE_CONNECTED) {
    	return NULL;
    }

    size_t mb_len = mbuf_get_left(mb);

    if (sf->bytes_accumulated < 8192 && sf->bytes_accumulated + mb_len >= 8192) {
    	struct mbuf *ping_mb = mbuf_alloc(512);
    	mbuf_set_end(ping_mb, 512);
    	ping_mb->pos = 512 - 12;
    	mbuf_write_u32(ping_mb, EVD_CORE_PING);
    	mbuf_write_u32(ping_mb, PING_MAGIC);
    	mbuf_write_u32(ping_mb, sf->bytes_accumulated);
    	mbuf_advance(ping_mb, -12);
        csock_forward(&sf->csock, ping_mb);
    }
    sf->bytes_accumulated += mb_len;
    return csock_next(&sf->csock, mb);
}

static struct csock *_incoming( struct csock *csock
							  , struct mbuf *mb )
{
	if (!csock || !mb)
		return NULL;

	debug("magi_eventdriver_init _incoming\n");

	struct magi_eventdriver *eventd = container_of(csock, struct magi_eventdriver, virtual_cs);

    ASSERT_TRUE(!((uintptr_t)(void *)mbuf_buf(mb) % 4) && "alignment");

    enum EVD_CORE ec = mbuf_read_u32(mb);
    ASSERT_TRUE(EVD_CORE_CHECKSIZE(ec, mbuf_get_left(mb)+4));
    uint32_t pfn = mbuf_read_u32(mb);
    mbuf_advance(mb, -4);
    mbuf_write_u32(mb, ec);
    mbuf_advance(mb, -4);

    if (pfn != 0xffffffff) { /* not a broadcast */
	    BREAKPOINT;
        /*struct Pathfinder* pf = ArrayList_Pathfinders_get(ee->pathfinders, pfn);
        ASSERT_TRUE(pf && pf->state == Pathfinder_state_CONNECTED);
        return sendToPathfinder(msg, pf);*/
    } else { /* do broadcast */
		struct le *le;
	    struct _starfinder *sf;
	    LIST_FOREACH(&eventd->starfinders, le) {
	        sf = le->data;
	        if (!sf || sf->state != STARFINDER_STATE_CONNECTED) {
	        	continue;
	        }
	        struct mbuf *mb_clone = mbuf_clone(mb);
	        CSOCK_CALL(_send_tosf, sf, mb_clone);
	        mb_clone = mem_deref(mb_clone);
	    }
    }

    return NULL;
}

static void magi_eventdriver_destructor(void *data)
{
    struct magi_eventdriver *ed = data;
    list_flush(&ed->starfinders);
    for (int i = 0; i < (EVD_STAR__TOO_HIGH - EVD_STAR__TOO_LOW); ++i) {
        list_flush(&ed->csocks[i]);
    }
}

int magi_eventdriver_init( struct magi_eventdriver **eventdp
						 , uint8_t pubkey[32] )
{
	struct magi_eventdriver *ed;

	if (!eventdp)
		return EINVAL;

	ed = mem_zalloc(sizeof(*ed), magi_eventdriver_destructor);
	if (!ed)
		return ENOMEM;

	ed->virtual_cs.send = _incoming;
    memcpy(ed->pubkey, pubkey, 32);

	list_init(&ed->starfinders);

	*eventdp = ed;

	return 0;
}
