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

#define TOSTR2(X) #X
#define TOSTR(X) TOSTR2(X)

struct _endnode {
	struct le le;
	struct addr addr;
};

#define __IN_START(fn) \
	static struct csock *fn( struct magi_starfinder *sf \
						   , struct mbuf *mb ) { \
		if (!sf || !mb)\
			return NULL;\
		debug(TOSTR(fn) "\n"); \

#define __IN_END(fn) \
		return NULL; \
	} \


struct _sf_ping {
	struct addr oaddr;
	struct magi_starfinder *sf;
	struct odict *outdict;
};

static void _sf_ping_destructor(void *data)
{
	struct _sf_ping *_p = data;
	_p->outdict = mem_deref(_p->outdict);
}


static void _send_ping_response( struct pl *_pl
							   , uint32_t version
							   , uint64_t ttl
							   , void *userdata )
{
	struct _sf_ping *_p = userdata;
	debug("sf _send_ping_response\n");
	if (!_p) {
		return;
	}

	if (!_pl || !_p->sf->for_ping_resp) { goto out; } /* timeout */

	/* this is so ugly... */
	struct odict *test_o = _p->sf->for_ping_resp;
	_p->sf->for_ping_resp = NULL;

	(void)test_o;

	/* check to make sure it is from the right peer.. */
	/* add to nodestore as a discovery or update */

	debug("LAYER 3 ENCRYPTED PING COMPLETE;\n");

out:
	_p = mem_deref(_p);
	return;

}

static void _send_ping_build(uint32_t hashid, uint64_t cookie, void *userdata)
{
	struct _sf_ping *_p = userdata;
	debug("sf _send_ping_build\n");
	if (!_p)
		return;

	struct PACKONE {
		 	uint32_t h;
		 	uint64_t c;
		 } subp = {.h = hashid, .c = cookie};

	struct pl pl_txid = {
		 .p = (const char *)&subp
		,.l = 12
	};
    odict_entry_add(_p->outdict, "txid", ODICT_STRING, &pl_txid);

	/* generate new mbuf and message */
	struct mbuf *mb = mbuf_alloc(512);
	mbuf_set_end(mb, 512);
	mb->pos = 512;
	mbuf_printf(mb, "%H", bencode_encode_odict, _p->outdict);
	/*mbuf_set_end(mb, mb->pos);*/
	mb->pos = 512;


	if (_p->oaddr.path == 1) {
		error("sending to ourselves...\n");
		BREAKPOINT;
	}

	ASSERT_TRUE(_p->oaddr.ip6.bytes[0] == 0xfc);

	mbuf_advance(mb, -EVD_CORE_MSG_LENGTH_MIN);
	memset(mbuf_buf(mb), 0, EVD_CORE_MSG_LENGTH_MIN);

	struct sess_wireheader *hdr = (struct sess_wireheader *)mbuf_buf(mb);
	struct wire_data *wdata = (struct wire_data *)(void *)&hdr[1];

	wire_data__ctype_set(wdata, EIPCTYPES_MAGI);
	wire_data__ver_set(wdata, 1);

	hdr->version_be = arch_htobe32(_p->oaddr.protover);
	hdr->sh.label_be = arch_htobe64(_p->oaddr.path);

	_wireheader_setversion(&hdr->sh, 1);

    memcpy(hdr->pubkey, _p->oaddr.key, 32);
    memcpy(hdr->ip6, _p->oaddr.ip6.bytes, 16);

    ASSERT_TRUE(!is_allzero(hdr->pubkey, 32));
    ASSERT_TRUE(hdr->version_be);
    ASSERT_TRUE(hdr->sh.label_be);

    mbuf_advance(mb, -4);
    mbuf_write_u32(mb, EVD_STAR_SENDMSG);
    mbuf_advance(mb, -4);
    csock_forward(&_p->sf->eventd_cs, mb);

    mem_deref(mb);

}

static int _send_evd_msg( struct magi_starfinder *sf
						, struct addr *oaddr
						, struct odict *outdict )
{

	struct _sf_ping *_p;

	_p = mem_zalloc(sizeof(*_p), _sf_ping_destructor);
	if (!_p)
		return ENOMEM;

	_p->sf = sf;
	memcpy(&_p->oaddr, oaddr, sizeof(struct addr));
	_p->outdict = mem_ref(outdict);

	mrpinger_ping( everip_mrpinger()
				 , 3000
				 , _send_ping_response
				 , _send_ping_build
				 , _p );

	return 0;
}

__IN_START(_do_connected)

	sf->state = STARFINDER_STATE_RUNNING;

__IN_END(_do_connected)


__IN_START(_in_msg)

	struct le *le;
	struct odict *outdict = NULL;
	const struct odict_entry *ode;

	struct addr in_addr;

	struct sess_wireheader *hdr = (struct sess_wireheader *)mbuf_buf(mb);

	mbuf_advance(mb, SESS_WIREHEADER_LENGTH + 4);

    memcpy(in_addr.ip6.bytes, hdr->ip6, 16);
    memcpy(in_addr.key, hdr->pubkey, 32);
    in_addr.protover = arch_betoh32(hdr->version_be);
    in_addr.padding = 0;
    in_addr.path = arch_betoh64(hdr->sh.label_be);

	struct odict *test_o = NULL;
	bencode_decode_odict( &test_o
						, 8
						, (const char *)mbuf_buf(mb)
						, mbuf_get_left(mb)
						, 2);

	if (test_o) {
		debug("MSG? %H\n", odict_debug, test_o);
	}

	ode = odict_lookup(test_o, "p");
	uint32_t version = ( ode
					  && ode->type == ODICT_INT
					  && ode->u.integer <= UINT32_MAX) ? (uint32_t)ode->u.integer : 0;

	const struct odict_entry *ode_txid = odict_lookup(test_o, "txid");
	const struct odict_entry *ode_q = odict_lookup(test_o, "q");
	if (ode_q) { /* HANDLE QUERY*/
		if (ode_q->type != ODICT_STRING || ode_q->u.pl.l < 2) {
			mem_deref(test_o);
			return NULL;
		}

		if (ode_q->u.pl.p[0] == 'g' && ode_q->u.pl.p[1] == 'p') {
			debug("Got a GP from version %u\n", version);
			/* now check for target*/
			ode = odict_lookup(test_o, "tar");
			if (!ode || ode->type != ODICT_STRING || ode->u.pl.l != 8) {
				mem_deref(test_o);
				return NULL;
			}
			uint64_t path_target = 0;
	        memcpy(&path_target, ode->u.pl.p, 8);
	        path_target = arch_betoh64(path_target);

	        /* begin result */
	        uint32_t count = list_count(&sf->endnodes);
	        uint8_t *out_data = mem_zalloc(count * ADDR_SERIALIZED_SIZE, NULL);

	        int ni = 0;
		    LIST_FOREACH(&sf->endnodes, le) {
		        struct _endnode *enode = le->data;
		        debug("%u enode %w\n", ni, enode->addr.key, ADDR_KEY_SIZE);
		        struct addr dummy_addr;
		        memcpy(&dummy_addr, &enode->addr, sizeof(struct addr));
		        dummy_addr.path = label_convertpov(dummy_addr.path, in_addr.path);
		        uint8_t *loc = &out_data[ni * ADDR_SERIALIZED_SIZE];
			    memcpy(loc, dummy_addr.key, ADDR_KEY_SIZE);
			    memcpy(loc+ADDR_KEY_SIZE, &dummy_addr.path, sizeof(dummy_addr.path));
		        ni++;
		    }

		    debug("CHECKKK: %w\n", out_data, count * ADDR_SERIALIZED_SIZE);

		    odict_alloc(&outdict, 8);
		    odict_entry_add(outdict, "p", ODICT_INT, EVERIP_VERSION_PROTOCOL);
		    struct pl n_pl = {
		    	 .p = (const char *)out_data
		    	,.l = count * ADDR_SERIALIZED_SIZE
		    };
		    odict_entry_add(outdict, "n", ODICT_STRING, &n_pl);
		    out_data = mem_deref(out_data);
		    /*odict_entry_add(outdict, "txid", ODICT_STRING, &n_pl);*/
		    /* np */

		    debug("OUTMSG? %H\n", odict_debug, outdict);

		} else {
			error("unknown query [%s]\n", ode->u.pl.p);
		}

	} else if (ode_txid) { /* HANDLE RESPONSE */
		/*BREAKPOINT;*/
		struct pl _dummy = {
			 .p = ode_txid->u.pl.p
			,.l = ode_txid->u.pl.l
		};
		debug("ode_txid\n");
		sf->for_ping_resp = (void *)test_o; /* this is so ugly */
		mrpinger_pong( everip_mrpinger(), version, &_dummy);
		sf->for_ping_resp = NULL;
	} else {
		error("UNKNOWN MAGI REQUEST!\n");
	}

	mem_deref(test_o);

	if (outdict) {
		/* prepare to send out! */

		outdict = mem_deref(outdict);
	}

__IN_END(_in_msg)

__IN_START(_in_switch_err)
__IN_END(_in_switch_err)

__IN_START(_in_search_req)
__IN_END(_in_search_req)

__IN_START(_in_peer)

/*
    uint8_t ip6[16];
    uint8_t pubkey[32];
    uint64_t path_be;
    uint32_t metric_be;
    uint32_t version_be;
*/

	struct addr oaddr;
	memset(&oaddr, 0, sizeof(struct addr));
	struct odict *outdict = NULL;
	mbuf_read_mem(mb, oaddr.ip6.bytes, 16);
	mbuf_read_mem(mb, oaddr.key, 32);
	oaddr.path = arch_betoh64(mbuf_read_u64(mb));
	mbuf_advance(mb, 4); /* skip metric */
	oaddr.protover = arch_betoh32(mbuf_read_u32(mb));

    odict_alloc(&outdict, 8);
    odict_entry_add(outdict, "p", ODICT_INT, (int64_t)EVERIP_VERSION_PROTOCOL);
    struct pl pl_gp = PL("gp");
    odict_entry_add(outdict, "q", ODICT_STRING, &pl_gp);

    struct pl pl_tar = PL("\x00\x00\x00\x00\x00\x00\x00\x00");
    odict_entry_add(outdict, "tar", ODICT_STRING, &pl_tar);

    odict_entry_add(outdict, "ei", ODICT_INT, (int64_t)0);

    debug("OUTMSG? %H\n", odict_debug, outdict);

    if (outdict) {
    	_send_evd_msg(sf, &oaddr, outdict);
    	outdict = mem_deref(outdict);
    }


	/*debug("\n\n[GOT PEER]\n[%w]\n[%w]\n\n",
		 ip6, 16
		,pubkey, 32
		);*/

	/*debug("READOUT [%w]\n", mb->buf, mb->size);*/

__IN_END(_in_peer)

__IN_START(_in_peer_gone)
__IN_END(_in_peer_gone)

__IN_START(_in_session)
__IN_END(_in_session)

__IN_START(_in_session_end)
__IN_END(_in_session_end)

__IN_START(_in_disco)
__IN_END(_in_disco)

__IN_START(_in_ping)
__IN_END(_in_ping)

__IN_START(_in_pong)
__IN_END(_in_pong)


static struct csock *_incoming_eventd( struct csock *csock
							         , struct mbuf *mb )
{
	if (!csock || !mb)
		return NULL;

	debug("_incoming_eventd\n");

	struct magi_starfinder *sf = container_of(csock, struct magi_starfinder, eventd_cs);

if (1) { /* possibly skip for UDP */

    enum EVD_CORE ec = mbuf_read_u32(mb);

    if (sf->state == STARFINDER_STATE_INITIALIZING) {
        ASSERT_TRUE(ec == EVD_CORE_CONNECT);
        return _do_connected(sf, mb);
    }

    sf->pathchangeinterval = 0;
    switch (ec) {
        case EVD_CORE_MSG: return _in_msg(sf, mb);
        case EVD_CORE_SWITCH_ERR: return _in_switch_err(sf, mb);
        case EVD_CORE_SEARCH_REQ: return _in_search_req(sf, mb);
        case EVD_CORE_PEER: return _in_peer(sf, mb);
        case EVD_CORE_PEER_GONE: return _in_peer_gone(sf, mb);
        case EVD_CORE_SESSION: return _in_session(sf, mb);
        case EVD_CORE_SESSION_ENDED: return _in_session_end(sf, mb);
        case EVD_CORE_DISCOVERED_PATH: return _in_disco(sf, mb);
        case EVD_CORE_PING: return _in_ping(sf, mb);
        case EVD_CORE_PONG: return _in_pong(sf, mb);
        default:;
    }
}
	return NULL;
}

static void _send_event( struct magi_starfinder *sf
					   , enum EVD_STAR es
					   , void *data
					   , size_t size )
{
	if (!sf) {
		return;
	}
	struct mbuf *mb = mbuf_alloc(512 + size);
	mbuf_set_end(mb, 512 + size);
	mb->pos = 512 - 4;
	mbuf_write_u32(mb, es);
	mbuf_write_mem(mb, data, size);
	mb->pos = 512 - 4;
    csock_forward(&sf->eventd_cs, mb);
    mb = mem_deref(mb);
}

static void _init_cb(void *arg)
{
	struct magi_starfinder *sf = arg;

	debug("_init_cb\n");

	struct PACKONE {
	    uint32_t super_be;
	    uint32_t ver_be;
	    uint8_t ua[64];
	} conn = {
		 .super_be = arch_htobe32(1)
		,.ver_be = arch_htobe32(EVERIP_VERSION_PROTOCOL)
	};

	_send_event(sf, EVD_STAR_CONNECT, &conn, 72);
	return;
}

static void _enode_destructor(void *data)
{
	struct _endnode *en = data;
	list_unlink(&en->le);
}

static void magi_starfinder_destructor(void *data)
{
	struct magi_starfinder *sf = data;
	sf->us = mem_deref(sf->us);
	tmr_cancel(&sf->tmr);
	list_flush(&sf->endnodes);
}

int magi_starfinder_init( struct magi_starfinder **starfinderp
						, uint8_t publickey[32] )
{
	struct magi_starfinder *sf;
	int err = 0;

	if (!starfinderp)
		return EINVAL;

	sf = mem_zalloc(sizeof(*sf), magi_starfinder_destructor);
	if (!sf)
		return ENOMEM;

	sf->eventd_cs.send = _incoming_eventd;

	list_init(&sf->endnodes);

	struct _endnode *selfenode;
	selfenode = mem_zalloc(sizeof(*selfenode), _enode_destructor);
	if (!selfenode)
		return ENOMEM;

	selfenode->addr.protover = EVERIP_VERSION_PROTOCOL;
	selfenode->addr.path = 1;
	memcpy(selfenode->addr.key, publickey, 32);
	list_append(&sf->endnodes, &selfenode->le, selfenode);


	/* register with eventdriver on the next tick */
	debug("X:S magi_starfinder_init\n");
	tmr_init(&sf->tmr);
	tmr_start(&sf->tmr, 0, _init_cb, sf);

	*starfinderp = sf;

/*out:*/
	if (err) {
		sf = mem_deref(sf);
	}
	return err;
}
