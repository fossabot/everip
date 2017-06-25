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

#include <sodium.h>

#if defined(HAVE_GENDO)
#include <gendo.h>
#endif

static struct everip {
	/* ritsuko */
	struct network *net;
	struct commands *commands;
	struct mrpinger *mrpinger;

	/* geofront */
	struct conduits *conduits;
	struct geofront *geofront;

	/* central dogma */
	struct caengine *caengine;
	struct cd_relaymap *cd_relaymap;
	struct cd_manager *cd_manager;
	struct cd_cmdcenter *cd_cmdcenter;

	/* terminal dogma */
	struct tmldogma *tmldogma;
	struct tunif *tunif;

	/* magi */
	struct magi_eventdriver *eventdriver;
	struct magi_starfinder *starfinder;

	/* treeoflife */
	struct treeoflife *treeoflife;

	struct netevent *netevent;

	struct csock tunif_cs;

	struct udp_sock *us;

	uint16_t udp_port;

} everip;

void everip_udpport_set(uint16_t port)
{
	everip.udp_port = port;
}

static struct csock *_from_terminaldogma( struct csock *csock
							       		, struct mbuf *mb )
{
	size_t top_pos = 0;
	struct treeoflife_peer *dst_peer;
	/*info("_from_terminaldogma\n");*/
#if 0
	struct everip *eip = container_of( csock
       								 , struct everip
       								 , tunif_cs);
#endif

	/* [PAYLOAD_TYPE][SENTKEY][HOP][SRC][DST] */

	mbuf_advance(mb, 4);

    struct _wire_ipv6_header *ihdr = \
        (struct _wire_ipv6_header *)mbuf_buf(mb);

	if (ihdr->dst[0] != 0xFC) {
		return NULL; /* toss */
	}

    uint16_t next_header = ihdr->next_header;
    uint8_t hop = ihdr->hop;

    uint8_t binlen;
    uint8_t binrep[ROUTE_LENGTH];

    memset(binrep, 0, ROUTE_LENGTH);

	if (!treeoflife_search( everip.treeoflife
					 , ihdr->dst+1
					 , &binlen
					 , binrep)) {
		return NULL;
	}

	debug("FOUND ROUTE FOR %W!\n[%u@%W]\n", ihdr->dst, KEY_LENGTH+1, binlen, binrep, ROUTE_LENGTH);

	dst_peer = treeoflife_route_to_peer(everip.treeoflife, binlen, binrep);

	if (!dst_peer) {
		debug("have route, but no one to send it to?\n");
		return NULL;
	}

	/*debug("READY TO SEND!!!\n");*/

	/*[TYPE(2)][KEY_LENGTH][DST_BINLEN(1)][DST_BINROUTE(ROUTE_LENGTH)][SRC_BINLEN(1)][SRC_BINROUTE(ROUTE_LENGTH)]*/

	mbuf_advance(mb, WIRE_IPV6_HEADER_LENGTH - (2+KEY_LENGTH+1+ROUTE_LENGTH+1+ROUTE_LENGTH));
    top_pos = mb->pos;
    mbuf_write_u16(mb, arch_htobe16(next_header));
    mbuf_write_mem(mb, everip.treeoflife->selfkey, KEY_LENGTH);

    /* DST */
    mbuf_write_u8(mb, binlen);
    mbuf_write_mem(mb, binrep, ROUTE_LENGTH);

	/* SRC */
    mbuf_write_u8(mb, everip.treeoflife->zone[0].binlen);
    mbuf_write_mem(mb, everip.treeoflife->zone[0].binrep, ROUTE_LENGTH);
    mbuf_set_pos(mb, top_pos);

	/*debug("ATTEMPTING SEND: [%W];\n", mbuf_buf(mb), mbuf_get_left(mb));*/

    if (everip.treeoflife->cb)
    	everip.treeoflife->cb(everip.treeoflife, dst_peer, mb);


	return NULL;
}

/* this function is a littlebit clunky,
   but needed for now */
static void _tree_cb( struct treeoflife *t
				    , struct treeoflife_peer *peer
				    , struct mbuf *mb)
{
	struct le *le;
	struct treeoflife_peer *p;
	struct mbuf *mb_clone;
	if (!peer) {
		/*debug("_tree_cb BROADCAST\n");*/
		LIST_FOREACH(&t->peers, le) {
			p = le->data;
			mb_clone = mbuf_clone(mb);
			debug("sending %u bytes to peer %J\n", mbuf_get_left(mb_clone), &p->sa);
			(void)udp_send(everip.us, &p->sa, mb_clone);
			mb_clone = mem_deref(mb_clone);
		}
	} else {
		debug("sending _tree_cb %J\n", &peer->sa);
		(void)udp_send(everip.us, &peer->sa, mb);
	}
	return;
}

static void _tree_tun_cb( struct treeoflife *t
					    , struct mbuf *mb)
{
	csock_next(&everip.tunif_cs, mb);
}

static void udp_recv_handler( const struct sa *src
							, struct mbuf *mb
							, void *arg )
{
	struct treeoflife_peer *p;
	(void)arg;

	(void)treeoflife_peer_find_or_new( &p
									 , everip.treeoflife
									 , src
									 , false);
	treeoflife_msg_recv(everip.treeoflife, p, mb, 1);

}

int everip_init(void)
{
	int err;
	struct sa laddr;

	memset(&everip, 0, sizeof(struct everip));

    if (sodium_init() == -1) {
        return EINVAL;
    }

	/* Initialise Network */
	err = net_alloc(&everip.net);
	if (err) {
		return err;
	}

#if 0
	err = mrpinger_init(&everip.mrpinger);
	if (err)
		return err;
#endif

	err = cmd_init(&everip.commands);
	if (err)
		return err;

	err = caengine_init(&everip.caengine);
	if (err)
		return err;

#if defined(HAVE_GENDO)
	GENDO_INIT;
#endif

	if (!everip.caengine->activated) {
		error("CAE: could not be activated...\n");
		err = EBADMSG;
		return err;
	}

	caengine_authtoken_add(everip.caengine, "EVERIP", "DEFAULT" );

	/* magi */
	err = magi_eventdriver_init( &everip.eventdriver, everip.caengine->my_pubkey );
	if (err)
		return err;

	/* init tree */
	err = treeoflife_init( &everip.treeoflife
		                 , everip.caengine->my_ipv6+1 );
	if (err)
		return err;

	treeoflife_register_cb(everip.treeoflife, _tree_cb);
	treeoflife_register_tuncb(everip.treeoflife, _tree_tun_cb);

	everip.tunif_cs.send = _from_terminaldogma;

	if (!everip.udp_port)
		everip.udp_port = 1988;

	(void)sa_set_str(&laddr, "0.0.0.0", everip.udp_port);

	debug("listening on UDP socket: %J\n", &laddr);

	/* Create listening UDP socket, IP address 0.0.0.0, UDP port 3456 */
	err = udp_listen( &everip.us
					, &laddr
					, udp_recv_handler
					, NULL);
	if (err) {
		return err;
	}

	udp_rxsz_set(everip.us, EVER_OUTWARD_MBE_LENGTH * 2); /* MTU 1500 max */
	udp_rxbuf_presz_set(everip.us, EVER_OUTWARD_MBE_POS);

	udp_sockbuf_set(everip.us, 24000);

#if 0
	/* central dogma */
	err = cd_relaymap_init(&everip.cd_relaymap);
	if (err)
		return err;

	err = cd_manager_init(&everip.cd_manager, everip.eventdriver);
	if (err)
		return err;

	err = geofront_init(&everip.geofront);
	if (err)
		return err;

	err = cd_cmdcenter_init(&everip.cd_cmdcenter, everip.caengine->my_pubkey);
	if (err)
		return err;


	err = conduits_init( &everip.conduits
		               , everip.cd_relaymap
		               , everip.cd_cmdcenter
		               , everip.eventdriver );
	if (err)
		return err;



	err = tmldogma_init( &everip.tmldogma
					   , everip.eventdriver
					   , everip.caengine->my_ipv6);
	if (err)
		return err;
#endif

	/* do connections */

	/* connect central dogma */
	//csock_flow(everip.cd_relaymap->router_cs, &everip.cd_manager->relaymap_cs);
	//csock_flow(&everip.cd_manager->cmdcenter_cs, &everip.cd_cmdcenter->manager_cs);

	/* connect terminal dogma to central dogma */
	//csock_flow( &everip.cd_manager->terminaldogma_cs
	//	      , &everip.tmldogma->ctrdogma_cs );

	/* starfinder */
#if 0
	err = magi_starfinder_init( &everip.starfinder, everip.caengine->my_pubkey);
	if (err)
		return err;

	magi_eventdriver_register_star(everip.eventdriver, &everip.starfinder->eventd_cs);
#endif

	/*net_change(everip.net, 2, NULL, NULL);*/
	err = netevent_init( &everip.netevent );
	if (err)
		return err;

	struct sa tmp_sa;
	sa_init(&tmp_sa, AF_INET6);
	sa_set_in6(&tmp_sa, everip.caengine->my_ipv6, 0);

	info("UNLOCKING LICENSED EVER/IP(R) ADDRESS\n%j\n", &tmp_sa, 16);

#if 1
#if !defined(WIN32) && !defined(CYGWIN)
	err = tunif_init( &everip.tunif );
	if (err)
		return err;

	err = net_if_setaddr( everip.tunif->name
		                , &tmp_sa
		                , 8 );
	if (err)
		return err;
	err = net_if_setmtu( everip.tunif->name
		               , 1304);
	if (err)
		return err;

	csock_flow( &everip.tunif->tmldogma_cs
			  , &everip.tunif_cs);

#endif
#endif

#if !defined(WIN32) && !defined(CYGWIN)
	module_preload("stdio");
#else
	module_preload("wincon");
#endif
	module_preload("dcmd");

	/* conduits*/
	//module_preload("udp");
	//module_preload("eth");

#if defined(HAVE_GENDO)
	GENDO_MID;
#endif

	return 0;
}


void everip_close(void)
{

#if defined(HAVE_GENDO)
	GENDO_DEINIT;
#endif

	everip.us = mem_deref(everip.us);

	everip.treeoflife = mem_deref(everip.treeoflife);

	everip.netevent = mem_deref(everip.netevent);

	/* reverse from init */
	everip.tunif = mem_deref(everip.tunif);

	everip.tmldogma = mem_deref(everip.tmldogma);
	/*everip.cd_cmdcenter = mem_deref(everip.cd_cmdcenter);*/
	everip.conduits = mem_deref(everip.conduits);
	/*everip.geofront = mem_deref(everip.geofront);*/
	/*everip.cd_manager = mem_deref(everip.cd_manager);*/
	/*everip.cd_relaymap = mem_deref(everip.cd_relaymap);*/
	everip.caengine = mem_deref(everip.caengine);

	everip.eventdriver = mem_deref(everip.eventdriver);
	/*everip.starfinder = mem_deref(everip.starfinder);*/

	everip.commands = mem_deref(everip.commands);
	/*everip.mrpinger = mem_deref(everip.mrpinger);*/
	everip.net = mem_deref(everip.net);
}


struct network *everip_network(void)
{
	return everip.net;
}

struct mrpinger *everip_mrpinger(void)
{
	return everip.mrpinger;
}

struct commands *everip_commands(void)
{
	return everip.commands;
}

struct caengine *everip_caengine(void)
{
	return everip.caengine;
}

struct conduits *everip_conduits(void)
{
	return everip.conduits;
}
struct treeoflife *everip_treeoflife(void)
{
	return everip.treeoflife;
}
