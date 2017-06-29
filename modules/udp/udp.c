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

struct udp_csock {
	struct csock csock;
	struct udp_sock *us;
	uint16_t port;
};

static struct csock *udp_handle_incoming( struct csock *csock
										, struct mbuf *mb )
{
	struct udp_csock *udp_c = (struct udp_csock *)csock;
	struct sa *dst;
	struct sa bcast;
	size_t pfix = mb->pos;

	mbuf_set_pos(mb, 0);
	struct csock_addr *csaddr = (struct csock_addr *) mbuf_buf(mb);

	if (csaddr->flags & CSOCK_ADDR_BCAST) {
		return NULL; /* not available on UDP */
	}

	if (csaddr->flags & CSOCK_ADDR_BCAST) {
		sa_set_str(&bcast, "255.255.255.255", udp_c->port);
		dst = &bcast;
	} else {
		dst = &csaddr->a.sa;
	}

	mbuf_set_pos(mb, pfix);

	debug("got %zu bytes of data FOR %J (salen=%u)\n",
		  mbuf_get_left(mb), dst, dst->len);

	(void)udp_send(udp_c->us, dst, mb);

	return NULL;
}

static void recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct udp_csock *udp_c = arg;
	size_t pfix = mb->pos;

	debug("got %zu bytes of UDP data from %J\n",
		  mbuf_get_left(mb), src);

	/*csock_addr_cpysa(mb, src);*/

	mbuf_set_pos(mb, 0);
	struct csock_addr *csaddr = (struct csock_addr *)mbuf_buf(mb);
	memset(csaddr, 0, sizeof(struct csock_addr));

	struct PACKONE {
		uint16_t flags;
		uint32_t hash;
	} tmp;

	tmp.flags = 0;
	tmp.hash = sa_hash(src, SA_ALL);

	csaddr->hash = hash_joaat((uint8_t *)&tmp, 6);
	csaddr->len = CSOCK_ADDR_LENTOP + src->len;
	csaddr->flags = tmp.flags;

	sa_cpy(&csaddr->a.sa, src);

	mbuf_set_pos(mb, pfix);
	csock_forward(&udp_c->csock, mb);
}

static void udp_c_destructor(void *data)
{
	struct udp_csock *udp_c = data;

	udp_c->us = mem_deref(udp_c->us);

	csock_stop(&udp_c->csock);

}

static struct udp_csock *udp_c = NULL;

static int module_init(void)
{
	int err = 0;
	struct sa laddr;

	udp_c = mem_zalloc(sizeof(*udp_c), udp_c_destructor);
	if (!udp_c)
		return ENOMEM;

	udp_c->port = 3456;

	(void)sa_set_str(&laddr, "0.0.0.0", udp_c->port);

	/* Create listening UDP socket, IP address 0.0.0.0, UDP port 3456 */
	err = udp_listen(&udp_c->us, &laddr, recv_handler, udp_c);
	if (err) {
		re_fprintf(stderr, "udp listen error: %s\n", strerror(err));
		goto out;
	}

	udp_rxsz_set(udp_c->us, EVER_OUTWARD_MBE_LENGTH*2); /* MTU 1500 max */
	udp_rxbuf_presz_set(udp_c->us, EVER_OUTWARD_MBE_POS);

	udp_sockbuf_set(udp_c->us, 24000);

	int enabled = 1;
	udp_setsockopt( udp_c->us
				  , SOL_SOCKET
				  , SO_BROADCAST
				  , &enabled
				  , sizeof(enabled));

	re_printf("listening on UDP socket: %J\n", &laddr);

	udp_c->csock.send = udp_handle_incoming;

	conduits_register( everip_conduits()
					 , "UDP"
					 , "UDP/IP Driver Conduit"
					 , (struct csock *)udp_c
					 );

out:
	if (err) {
		mem_deref(udp_c->us);
		mem_deref(udp_c);
	}
	return err;
}


static int module_close(void)
{

	udp_c = mem_deref(udp_c);

	return 0;
}


const struct mod_export DECL_EXPORTS(udp) = {
	"udp",
	"conduit",
	module_init,
	module_close
};
