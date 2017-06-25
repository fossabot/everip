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
#include <string.h>

#define MSEC_PEER_FORGET (256*1024)
#define MSEC_PEER_UNRESPONSIVE (20*1024)
#define MSEC_PING_LAZY (3*1024)
#define MSEC_PING_INTERVAL 1024
#define MSEC_PING_TIMEOUT (2*1024)
#define MSEC_BEACON_INTERVAL 16000

struct conduits {
	struct list condl;
	struct hash *peers;
	struct list allpeers;

	struct csock eventd_cs;

	struct cd_relaymap *relaymap;
	struct cd_cmdcenter *cmdcenter;

	struct tmr interval_tmr;
	struct tmr beacon_tmr;

	struct wire_beacon beacon;

};

static void _send_ping(struct conduit_peer *p);

static void _send_event_peer( struct conduit_peer *p
	                        , uint32_t sf_id
	                        , enum EVD_CORE ec )
{

	struct mbuf *mb = mbuf_alloc(512 + 8 + 64);
	mbuf_set_end(mb, mb->size);
	mb->pos = 512;

	mbuf_write_u32(mb, ec);
	mbuf_write_u32(mb, sf_id);

	/* write-out peer */
	mbuf_write_mem(mb, p->addr.ip6.bytes, 16);
	mbuf_write_mem(mb, p->addr.key, 32);

	mbuf_write_u64(mb, arch_htobe64( p->addr.path ));
	mbuf_write_u32(mb, sf_id);
	mbuf_write_u32(mb, arch_htobe32( p->addr.protover ));

	mbuf_advance(mb, -(8 + 64));

	/*debug("READOUT [%w]\n", mb->buf, mb->size);*/

    csock_forward(&p->conduit->ctx->eventd_cs, mb);
    mb = mem_deref(mb);
}


static void peer_destructor(void *data)
{
	struct conduit_peer *p = data;

	_send_event_peer(p, 0xffffffff, EVD_CORE_PEER_GONE);

	p->caes = mem_deref(p->caes);
	list_unlink(&p->le);
	list_unlink(&p->le_all);
}

static void _interval_cb(void *arg)
{
	struct conduits *c = arg;

	struct le *le;
	struct conduit_peer *p;

	if (!c)
		return;

	uint64_t now = tmr_jiffies();

	LIST_FOREACH(&c->allpeers, le) {
		p = le->data;
		if (!p)
			continue;

		if (p->addr.protover && now < p->lastmsg_ts + MSEC_PING_LAZY) {
			if (p->state == CONDUIT_PEERSTATE_ESTABLISHED) {
				_send_event_peer(p, 0xffffffff, EVD_CORE_PEER);
			}
			return;
		}

        if (now < p->lastping_ts + MSEC_PING_LAZY) {
            return;
        }

        if (p->outside_initiation && now > p->lastmsg_ts + MSEC_PEER_FORGET) {
        	info("unresponsive peer [%w][%ums]\n", p->caes->remote_pubkey, 32, MSEC_PEER_FORGET);
        	_send_event_peer(p, 0xffffffff, EVD_CORE_PEER_GONE);
        	p = mem_deref(p);
            return;
        }

        bool unresponsive = (now > p->lastmsg_ts + MSEC_PEER_UNRESPONSIVE);
        if (unresponsive) {
            if (p->cnt_ping % 8) {
                p->cnt_ping++;
                return;
            }

            _send_event_peer(p, 0xffffffff, EVD_CORE_PEER_GONE);
            p->state = CONDUIT_PEERSTATE_UNRESPONSIVE;
            cd_relaymap_slot_setstate( (struct cd_relaymap_slot *)&p->relaymap_cs
            	                     , RELAYMAP_SLOT_STATE_DOWN);
        }

		_send_ping(p);
	}

	tmr_start( &c->interval_tmr, MSEC_PING_INTERVAL, _interval_cb, c);
}

static void _beacon_cb(void *arg)
{
	struct le *le;
	struct mbuf *mb;
	struct conduits *c = arg;

	if (!c)
		return;

	struct csock_addr csaddr = {
		 .len = CSOCK_ADDR_LENTOP
		,.flags = CSOCK_ADDR_BCAST
	};

    struct conduit *_c;
    LIST_FOREACH(&c->condl, le) {
        _c = le->data;

		mb = mbuf_alloc(512);
		mbuf_set_end(mb, 512);
		csock_addr_cpycsa(mb, &csaddr);
		mbuf_set_pos(mb, 512 - WIRE_BEACON_LENGTH);
		mbuf_write_mem(mb, (void*)&c->beacon, WIRE_BEACON_LENGTH);

		mbuf_set_pos(mb, 512 - WIRE_BEACON_LENGTH);
        csock_next(&_c->csock, mb);
        mb = mem_deref(mb);
    }

    tmr_start( &c->beacon_tmr, MSEC_BEACON_INTERVAL, _beacon_cb, c);

}

static struct csock *_from_eventd( struct csock *csock
								 , struct mbuf *mb )
{
	BREAKPOINT;
	return NULL;
}

int conduits_debug(struct re_printf *pf, const struct conduits *conduits)
{
	int err;
	struct le *le;
	if (!conduits)
		return 0;

	err  = re_hprintf(pf, "[Peers and Conduits]\n");
	err  = re_hprintf(pf, "  [Field IX(TM)]\n");

	if (!conduits->allpeers.head) {
		err  = re_hprintf(pf, "    ■ {NO FIELD IX PEERS PRESENT}\n");
	}

	struct conduit_peer *p;
    LIST_FOREACH(&conduits->allpeers, le) {
        p = le->data;
        err  = re_hprintf( pf
        				 , "    [%w] STATE[%d] IN[%llu] OUT[%llu]\n"
        				 , p->caes->remote_ip6, 16
        				 , p->state
        				 , p->bytes_in, p->bytes_out);
        /*err  = re_hprintf(pf, "\tSTATE = %s\n", );*/
        /*i++;*/
    }


	err  = re_hprintf(pf, "  [Conduit Drivers]\n");
    struct conduit *c;
    int i = 0;
    LIST_FOREACH(&conduits->condl, le) {
        c = le->data;
        err  = re_hprintf(pf, "    ■ %s (%s)\n", c->name, c->desc);
        /*err  = re_hprintf(pf, "\tSTATE = %s\n", );*/
        i++;
    }

    err  = re_hprintf(pf, "\n[END]\n\n");

    return err;
}

static void conduits_destructor(void *data)
{
	struct conduits *conduits = data;
	hash_flush(conduits->peers);
	list_flush(&conduits->condl);
	conduits->peers = mem_deref(conduits->peers);
	tmr_cancel(&conduits->interval_tmr);
	tmr_cancel(&conduits->beacon_tmr);
}

int conduits_init( struct conduits **conduitsp
	             , struct cd_relaymap *relaymap
	             , struct cd_cmdcenter *cmdcenter
	             , struct magi_eventdriver *eventdriver )
{
	struct conduits *conduits;

	if (!conduitsp || !relaymap)
		return EINVAL;

	conduits = mem_zalloc(sizeof(*conduits), conduits_destructor);
	if (!conduits)
		return ENOMEM;

	list_init(&conduits->condl);
	list_init(&conduits->allpeers);
	hash_alloc(&conduits->peers, 128);

	conduits->relaymap = relaymap;
	conduits->cmdcenter = cmdcenter;

	conduits->beacon.ver_be = arch_htobe32(EVERIP_VERSION_PROTOCOL);

	memcpy( conduits->beacon.pubkey
		  , everip_caengine()->my_pubkey
		  , 32);

	/* initiate beacon */
	tmr_start( &conduits->interval_tmr
			 , MSEC_PING_INTERVAL
			 , _interval_cb
			 , conduits );

#if 1
	tmr_start( &conduits->beacon_tmr
			 , 0 /* start on next tick */
			 , _beacon_cb
			 , conduits );
#endif

	/* hook into events */
	conduits->eventd_cs.send = _from_eventd;
	magi_eventdriver_register_core( eventdriver
								  , &conduits->eventd_cs
								  , EVD_STAR_PEERS);

	*conduitsp = conduits;

	return 0;
}


struct conduit *conduit_find(const struct conduits *conduits,
		       const struct conduit *conduit)
{
	struct le *le;

	if (!conduits || !conduit)
		return NULL;

	for (le = conduits->condl.head; le; le = le->next) {
		struct conduit *c = le->data;

		if (c == conduit)
			return c;
	}

	return NULL;
}

static bool _peer_find_cb(struct le *le, void *arg)
{
        struct conduit_peer *p = le->data;
        struct csock_addr *csaddr = arg;

        if ( csaddr->flags & CSOCK_ADDR_MAC ) {
        	return 0 == memcmp(&csaddr->a.mac, &p->csaddr.a.mac, 6);
        } else {
        	return sa_cmp(&csaddr->a.sa, &p->csaddr.a.sa, SA_ALL);
        }
}

struct conduit_peer *conduits_peer_find( const struct conduits *conduits
							   		   , const struct csock_addr *csaddr )
{
        if (!conduits || !csaddr)
                return NULL;

         /*debug("HASH IS SET TO %u\n", csaddr->hash);*/

        return list_ledata(hash_lookup( conduits->peers
        							  , csaddr->hash
        							  , _peer_find_cb
        							  , (void *)csaddr));
}



static struct csock *_relaymap_send( struct csock *csock
								   , struct mbuf *mb)
{

	if (!csock || !mb)
		return NULL;

	/*debug("_relaymap_send\n");*/

	struct conduit_peer *p = (struct conduit_peer *)csock;

	p->bytes_out += mbuf_get_left(mb);

	/* encrypt */
    ASSERT_TRUE(!caengine_session_encrypt(p->caes, mb));
    ASSERT_TRUE(!(((uintptr_t)mb->buf) % 4) && "alignment fault");

    /*re_printf("GOT ALL THE WAY HERE!\n%w\n", mbuf_buf(mb), mbuf_get_left(mb));*/

    size_t out_pos = mb->pos;

    csock_addr_cpycsa(mb, &p->csaddr);

    /*re_printf("AND COPIED!\n");*/

    mbuf_set_pos(mb, out_pos);

    csock_forward(&p->conduit->csock, mb);

	return NULL;
}

static void _send_ping_response(struct pl *_pl, uint32_t version, uint64_t ttl, void *userdata)
{
	struct conduit_peer *p = userdata;
	/*debug("_send_ping_response\n");*/
	if (!p) {
		return;
	}

	if (!_pl) return; /* we failed... */

	ASSERT_TRUE(version);

	p->addr.protover = version;

	if (p->state == CONDUIT_PEERSTATE_ESTABLISHED) {
		_send_event_peer(p, 0xffffffff, EVD_CORE_PEER);
	}

	p->lastping_ts = tmr_jiffies();

}

static void _send_ping_build(uint32_t hashid, uint64_t cookie, void *userdata)
{
	struct conduit_peer *p = userdata;
	/*debug("_send_ping_build\n");*/

	if (!p)
		return;


	/* generate new mbuf and message */
	struct mbuf *mb = mbuf_alloc(512);
	mbuf_set_end(mb, 512);
	mb->pos = 512 - 12;
	mbuf_write_u32(mb, hashid);
	mbuf_write_u64(mb, cookie);
	mb->pos = 512 - 12;


	bool key = false; /* ? */

	/**/
	mbuf_advance(mb, -(CTRL_HEADER_LENGTH + 8 + (key ? 32 : 0)));
	size_t ctrlhead_pos = mb->pos;

    mbuf_advance(mb, 2); /* skip checksum */
    mbuf_write_u16(mb, (key ? CTRL_TYPE_PINGKEY_be : CTRL_TYPE_PING_be )); /* write new type */
    mbuf_write_u32(mb, arch_htobe32((key ? 0x01234567 : 0x09f91102 ))); /* write new magic */
    mbuf_write_u32(mb, arch_htobe32(EVERIP_VERSION_PROTOCOL)); /* write version */

	if (key) { /* keyping */
		mbuf_write_mem(mb, everip_caengine()->my_pubkey, 32);
	}

	/* calculate checksum... */
    mbuf_set_pos(mb, ctrlhead_pos);
    /*debug("CMD LENGTH == [%u]\n", mb->end - mb->pos);*/
    mbuf_write_u16(mb, 0); /* reset for checksum */
    mbuf_set_pos(mb, ctrlhead_pos);
    mbuf_write_u16(mb, chksum_buf(mbuf_buf(mb), mbuf_get_left(mb)) );
    mbuf_set_pos(mb, ctrlhead_pos);

    /* slap-on a routeheader!! */
    mbuf_advance(mb, -(SESS_WIREHEADER_LENGTH));
    struct sess_wireheader *out_sess_wh = (struct sess_wireheader *)mbuf_buf(mb);
    memset(out_sess_wh, 0, SESS_WIREHEADER_LENGTH);

    _wireheader_setversion(&out_sess_wh->sh, 1); /* current version is 1 */
    out_sess_wh->sh.label_be = arch_htobe64(p->addr.path);
    out_sess_wh->flags |= SESS_WIREHEADER_flags_CTRLMSG;

    /*BREAKPOINT;*/

    cd_cmdcenter_sendcmd(p->conduit->ctx->cmdcenter, mb );

    mb = mem_deref(mb);

}

static void _send_ping(struct conduit_peer *p)
{
	if (!p)
		return;

	debug("_send_ping\n");
	p->cnt_ping++;

	mrpinger_ping( everip_mrpinger()
				 , 3000
				 , _send_ping_response
				 , _send_ping_build
				 , p );

	return;

}

static struct conduit_peer *
conduit_peer_create( struct conduit *conduit
				   , const struct csock_addr *csaddr
				   , const uint8_t remote_pubkey[32]
				   , bool outside_initiation )
{
	int err = 0;
	struct conduit_peer *p;
	p = mem_zalloc(sizeof(*p), peer_destructor);
	if (!p)
		return NULL;

	debug("\n\nNEW PEER\n\n");

	p->conduit = conduit;

	ASSERT_TRUE(csaddr->len <= sizeof(struct csock_addr));
	memcpy(&p->csaddr, csaddr, sizeof(struct csock_addr));

/*	debug("csaddr->len = %u|%u\n", (&p->csaddr)->len, (&p->csaddr)->a.sa.len);
*/

	/*debug("HASH IS SET TO %u\n", csaddr->hash);*/

	hash_append( conduit->ctx->peers
			   , csaddr->hash
			   , &p->le
			   , p
			   );

	list_append(&conduit->ctx->allpeers, &p->le_all, p);

	/* create cae_session */
	err = caengine_session_new( &p->caes
							  , everip_caengine()
							  , remote_pubkey
							  , ( outside_initiation ? true : false));
	if (err) {
		error("caengine_session_new %m", err);
		p = mem_deref(p);
		return NULL;
	}

	p->outside_initiation = outside_initiation;

	/* setup timers */
	p->lastmsg_ts =   tmr_jiffies()
					- MSEC_PING_LAZY
					- 1;

	return p;
}

static struct csock *conduits_handle_beacon( struct conduit *conduit
										   , struct csock_addr *csaddr
										   , struct mbuf *mb)
{
	if (!conduit || !csaddr || !mb)
		return NULL;

	debug( "conduits_handle_beacon [%u] from %J\n"
		     , mbuf_get_left(mb)
		     , &csaddr->a.sa);

	struct wire_beacon *beacon = (struct wire_beacon *)(void *)mbuf_buf(mb);

	/* check version */
	if (!everip_version_compat(EVERIP_VERSION_PROTOCOL, arch_betoh32(beacon->ver_be))) {
		debug("beacon: invalid version [%u];\n", arch_betoh32(beacon->ver_be));
		return NULL;
	}

	uint8_t check_address[16];
	addr_calc_pubkeyaddr(check_address, beacon->pubkey);

	if (check_address[0] != 0xfc || !memcmp(everip_caengine()->my_pubkey, beacon->pubkey, 32)) {
        debug("beacon: invalid key [%w]\n", check_address, 16);
        return NULL;
    }

    struct conduit_peer *p = conduits_peer_find(conduit->ctx, csaddr);

    if (p) {
    	debug("ignoring peer beacon [%w];\n", check_address, 16);
    	return NULL;
    }

	/* X:TODO calculate address and make sure it is us*/

	conduits_peer_bootstrap( conduit
						   , conduit->ctx
						   , false
						   , beacon->pubkey
						   , csaddr
						   , "DEFAULT"
						   , NULL /*"[FIELD IX]"*/
						   , NULL);


	return NULL;

}

static void _conduits_process_endpoints( struct conduits *c
									   , struct conduit_peer *p)
{
	struct le *le;
	struct conduit_peer *_p;
    LIST_FOREACH(&c->allpeers, le) {
    	_p = le->data;
    	if (p != _p && !memcmp(p->addr.key, _p->addr.key, 32)) {
    		/* similar peers?? */
    		if (p->conduit == _p->conduit) {
    			/* update and destroy old peer */
	            p->addr.path = _p->addr.path;
	            p->relaymap_cs.adj = _p->relaymap_cs.adj;
	            p->relaymap_cs.adj->adj = &p->relaymap_cs;
	            _p->relaymap_cs.adj = NULL;
	            _p = mem_deref(_p);
	            return;
    		}
    	}
	}
	return;
}

static struct csock *conduits_handle_incoming( struct csock *csock
											 , struct mbuf *mb)
{
	int err = 0;

	struct conduit *conduit = (struct conduit *)csock;

	size_t pfix = mb->pos;
	mbuf_set_pos(mb, 0);
	struct csock_addr *csaddr = (struct csock_addr *) mbuf_buf(mb);

	mbuf_set_pos(mb, pfix);

	if (mbuf_get_left(mb) == WIRE_BEACON_LENGTH) {
		return conduits_handle_beacon(conduit, csaddr, mb);
	}


	struct conduit_peer *p = conduits_peer_find(conduit->ctx, csaddr);

	debug("conduits_handle_incoming [%u] on %s\n"
		     , mbuf_get_left(mb)
		     , conduit->name);

	debug("peer? %p\n", p);

	if (!p) {
		if (mbuf_get_left(mb) < CAE_HEADER_LENGTH)
			return NULL;

	    uint8_t remote_pubkey[32];
	    mbuf_set_pos(mb, pfix + (4 + 12 + 24));
	    mbuf_read_mem(mb, remote_pubkey, 32);
		debug("remote_pubkey = %w\n", remote_pubkey, 32);
		p = conduit_peer_create( conduit
							   , csaddr
							   , remote_pubkey
							   , true );

		if (!p) {
			return NULL;
		}

		mbuf_set_pos(mb, pfix);
		if (caengine_session_decrypt(p->caes, mb)) {
			p = mem_deref(p);
			return NULL;
		}

		p->relaymap_cs.send = _relaymap_send;

		err = cd_relaymap_slot_add( &p->addr.path
			          		      , conduit->ctx->relaymap
					 		      , &p->relaymap_cs );
		if (err) {
			p = mem_deref(p);
			return NULL;
		}

	} else {
		/* HAVE a PEER! */
	    caengine_session_resetiftimedout(p->caes);
	    mbuf_set_pos(mb, pfix);
		if (caengine_session_decrypt(p->caes, mb)) {
			return NULL;
		}
		p->bytes_in += mbuf_get_left(mb);
		/*X:TODO plink_recv;*/
	}

	/*re_printf("GOT SOME DATA DAD! = %w\n", mbuf_buf(mb), mbuf_get_left(mb));*/

	/*goto post_caengine;*/

	(void)mb;

/*post_caengine:*/

	enum CAENGINE_STATE cae_state = caengine_session_state(p->caes);

    if (p->state < CONDUIT_PEERSTATE_ESTABLISHED) {
        p->state = (enum CONDUIT_PEERSTATE)cae_state;
        cd_relaymap_slot_setstate((struct cd_relaymap_slot *)&p->relaymap_cs, RELAYMAP_SLOT_STATE_ISUP);

        memcpy(p->addr.key, p->caes->remote_pubkey, 32);
        addr_prefix(&p->addr);

        if (cae_state == CAENGINE_STATE_ESTABLISHED) {
            /*error("X:TODO update_endpoint(ep);\n");*/
            _conduits_process_endpoints(conduit->ctx, p);
        } else {
            if (mbuf_get_left(mb) < 8 || mbuf_buf(mb)[7] != 1) {
                error("DROP: NO CAE?\n");
                return 0;
            } else {
                if ((p->cnt_ping + 1) % 7) {
                    _send_ping(p);
                }
            }
        }
    } else if (p->state == CONDUIT_PEERSTATE_UNRESPONSIVE
        && cae_state == CAENGINE_STATE_ESTABLISHED)
    {
        p->state = CONDUIT_PEERSTATE_ESTABLISHED;
        cd_relaymap_slot_setstate((struct cd_relaymap_slot *)&p->relaymap_cs, RELAYMAP_SLOT_STATE_ISUP);
    } else {
        p->lastmsg_ts = tmr_jiffies();
    }


    return csock_next(&p->relaymap_cs, mb);

	return NULL;
}

int conduits_peer_bootstrap( struct conduit *conduit
						   , struct conduits *c
						   , bool outside_initiation
						   , const uint8_t *remote_pubkey
						   , const struct csock_addr *csaddr
						   , const char *pword
						   , const char *login
						   , const char *identifier )
{
	int err = 0;
	struct conduit_peer *p;

	if (!conduit || !c || !remote_pubkey)
		return EINVAL;

	debug("conduits_peer_bootstrap [%J]\n", &csaddr->a.sa);
	/* get conduit from conduit_id */

	/* calculate address for validity */

	/* create new peer */
	/* create new caession for peer */
	p = conduit_peer_create( conduit
						   , csaddr
						   , remote_pubkey
						   , outside_initiation );


	/* set authentation as required */
	caengine_session_setauth(p->caes, pword, login);

	/* initiate flow between relaymap and peer */
	p->relaymap_cs.send = _relaymap_send;
	err = cd_relaymap_slot_add( &p->addr.path
		          		      , c->relaymap
				 		      , &p->relaymap_cs );
	if (err) {
		p = mem_deref(p);
		return EINVAL;
	}

	/* send ping! */
	_send_ping(p);

	return 0;
}

static void conduit_destructor(void *data)
{
	struct conduit *c = data;

	c->name = mem_deref(c->name);
	c->desc = mem_deref(c->desc);

	csock_stop(&c->csock);
}

/**
 * Register conduits
 *
 *
 * @return 0 if success, otherwise errorcode
 */
int conduits_register( struct conduits *conduits
					 , const char *name
					 , const char *desc
					 , struct csock *csock )
{
	struct conduit *c;

	if (!conduits || !name || !desc || !csock)
		return EINVAL;

	c = mem_zalloc(sizeof(*c), conduit_destructor);
	if (!c)
		return ENOMEM;

	str_dup(&c->name, name);
	str_dup(&c->desc, desc);

	c->ctx = conduits;

	c->csock.send = conduits_handle_incoming;
	/* setup flow */
	csock_flow(csock, &c->csock);

	list_append(&conduits->condl, &c->le, c);

	return 0;
}

