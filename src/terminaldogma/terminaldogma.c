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

static struct csock *_from_ctrdogma( struct csock *csock
							       , struct mbuf *mb )
{
	if (!csock || !mb)
		return NULL;

	struct tmldogma *tdogma = container_of(csock, struct tmldogma, ctrdogma_cs);

    ASSERT_TRUE(mbuf_get_left(mb) >= SESS_WIREHEADER_LENGTH);

	struct sess_wireheader *hdr = (struct sess_wireheader *)mbuf_buf(mb);

	ASSERT_TRUE(mbuf_get_left(mb) >= SESS_WIREHEADER_LENGTH + WIRE_DATA_LASTESTVERSION);
    struct wire_data* dhdr = (struct wire_data*)(void *)&hdr[1];

    enum EIPCTYPES type = wire_data__ctype_get(dhdr);

    if (type <= EIPCTYPES_IP6_MAX) {
    	debug("type == EIPCTYPES_IP6_MAX\n");
    	/*error("(%u[%w]\n", mbuf_get_left(mb), mbuf_buf(mb), mbuf_get_left(mb));*/

	    memmove(hdr->ip6 + WIRE_DATA_LENGTH - 16, hdr->ip6, 16);
	    memcpy(&hdr->ip6[WIRE_DATA_LENGTH], tdogma->ip6, 16);

	    mbuf_advance( mb
	    			 , -( WIRE_IPV6_HEADER_LENGTH
	    			 	- WIRE_DATA_LENGTH
	    			 	- SESS_WIREHEADER_LENGTH)
	    			 );

	    struct _wire_ipv6_header *ihdr = \
		(struct _wire_ipv6_header *)mbuf_buf(mb);

		/* zero-out everything but addresses */
	    memset(ihdr, 0, WIRE_IPV6_HEADER_LENGTH - 32);
	    ((uint8_t*)ihdr)[0] |= (6) << 4;

	    ihdr->hop = 42;
	    ihdr->next_header = type;
	    ihdr->payload_be = arch_betoh16(mbuf_get_left(mb) - WIRE_IPV6_HEADER_LENGTH);

	    mbuf_advance(mb, -4);
	    ((uint16_t*)(void *)mbuf_buf(mb))[0] = 0;
	    ((uint16_t*)(void *)mbuf_buf(mb))[1] = arch_htobe16(0x86DD);

        return csock_next(&tdogma->tunadapt_cs, mb);
    }
    if (type == EIPCTYPES_MAGI) {
    	debug("type == EIPCTYPES_MAGI\n");
    	mbuf_advance(mb, -8);
    	mbuf_write_u32(mb, EVD_CORE_MSG);
    	mbuf_write_u32(mb, 0xffffffff);
    	mbuf_advance(mb, -8);
    	return csock_next(&tdogma->eventd_cs, mb);
    }
    debug("DROP buffer with unknown type [%d]\n", type);
    return NULL;
}

static struct csock *_from_tunadapt( struct csock *csock
							       , struct mbuf *mb )
{
	if (!csock || !mb)
		return NULL;

	struct tmldogma *t = container_of( csock
									 , struct tmldogma
									 , tunadapt_cs );

	size_t top_pos = mb->pos;

	mbuf_advance(mb, 2);
	uint16_t ethertype = mbuf_read_u16(mb);
	int ip_version = (((uint8_t*)mbuf_buf(mb))[0] & 0xF0) >> 4;

	if (6 != ip_version) {
		/* only supporting ipv6 */
		return NULL;
	}

	if (ethertype != arch_htobe16(0x86DD)) {
		/* ONLY SUPPORTING IPV6 */
		return NULL;
	}

	if (mbuf_get_left(mb) < 40) {
		/* what is this? it is certainly not ipv6... */
		return NULL;
	}

	struct _wire_ipv6_header *hdr = \
		(struct _wire_ipv6_header *)mbuf_buf(mb);

#if 1
	debug("_from_tunadapt: [%u][%d]\n", ethertype, ip_version);
	debug("SRC: %w\n", hdr->src, 16);
	debug("DST: %w\n", hdr->dst, 16);
#endif

	if (memcmp(hdr->src, t->ip6, 16)) {
		/* packet must come from us */
		return NULL;
	}

	if (!memcmp(hdr->dst, t->ip6, 16)) {
		/* note to self... */
		mbuf_set_pos(mb, top_pos);
		return csock_next(csock, mb);;
	}

	/* slap-on headers */

	debug("checking headers...\n");

	/* make room for wdata header */
	memmove( hdr->dst - WIRE_DATA_LENGTH
		   , hdr->dst
		   , 16);

	mbuf_advance(mb, -( WIRE_DATA_LENGTH
					  + SESS_WIREHEADER_LENGTH
					  - WIRE_IPV6_HEADER_LENGTH));

	struct sess_wireheader *shdr = (struct sess_wireheader *)mbuf_buf(mb);
	struct wire_data* dhdr = (struct wire_data*)(void *)&shdr[1];
	memset(dhdr, 0, WIRE_DATA_LENGTH);

	wire_data__ctype_set(dhdr, hdr->next_header);
	wire_data__ver_set(dhdr, 1); /* version set to 1 */

	memset(shdr, 0, SESS_WIREHEADER_LENGTH - 16);

	return csock_next(&t->ctrdogma_cs, mb);
}

static struct csock *_from_eventd( struct csock *csock
							     , struct mbuf *mb )
{
	if (!csock || !mb)
		return NULL;

	return NULL;
}

static void tmldogma_destructor(void *data)
{
	struct tmldogma *t = data;
	(void)t;
}

int tmldogma_init( struct tmldogma **tmldogmap
				 , struct magi_eventdriver *eventd
				 , uint8_t ip6[16] )
{
	struct tmldogma *t;

	if (!tmldogmap)
		return EINVAL;

	t = mem_zalloc(sizeof(*t), tmldogma_destructor);
	if (!t)
		return ENOMEM;

	memcpy(t->ip6, ip6, 16);

	t->ctrdogma_cs.send = _from_ctrdogma;
	t->tunadapt_cs.send = _from_tunadapt;

	t->eventd_cs.send = _from_eventd;
	/*magi_eventdriver_register_core(eventd, &t->eventd_cs, EVD_STAR_SENDMSG );*/

	*tmldogmap = t;

	return 0;
}


