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

#define RELAYMAP_ASSERT_TRUE(x) if (!(x)) {BREAKPOINT;}

static inline struct csock * _send_err( struct cd_relaymap_slot *slot
									  , struct mbuf *mb
									  , uint32_t ecode)
{
	if (!slot || !mb)
		return NULL;

    size_t pfix = mb->pos;

	struct rmap_wireheader whead;
	mbuf_read_mem(mb, (uint8_t *)&whead, sizeof(struct rmap_wireheader));

	if (whead.cas & 1) { /* suppress errors */
		return NULL;
	}

	mbuf_set_pos(mb, pfix);

    if ((mb->size - mb->pos) > CTRL_HEADER_ERRLENGTHMAX) {
    	mb->end = mb->pos + CTRL_HEADER_ERRLENGTHMAX;
    }

    mbuf_advance(mb, -(RELAYMAP_HEADER_LENGTH
    	  		     + 4 /* handle */
      				 + CTRL_HEADER_LENGTH
    				 + CTRL_HEADER_ERRLENGTH));

    /* check to make sure we are still in the scratchpad */
    /*RELAYMAP_ASSERT_TRUE(mb_cause->pos > mbe->s);*/

    /* we have a new header location now... */
    size_t header_pos = mb->pos;

    whead.label_be = reverse_b64(whead.label_be);
    _wireheader_setversion(&whead, 1);
    _wireheader_setcongestion(&whead, 0);
	_wireheader_setsuppresson(&whead, true);
	_wireheader_setpenalty(&whead, 0);

    /* write out! */
    mbuf_write_mem(mb, (uint8_t *)&whead, sizeof(struct rmap_wireheader));
    mbuf_write_u32(mb, 0xffffffff); /* handle */
    uint16_t checksum_pos = mb->pos;
    mbuf_write_u16(mb, 0); /* checksum, will calc later */
    mbuf_write_u16(mb, CTRL_TYPE_ERROR_be);
    mbuf_write_u32(mb, arch_htobe32(ecode)); /* error code */

    mbuf_set_pos(mb, checksum_pos);
    mbuf_write_u16( mb
    			  , chksum_buf(mbuf_buf(mb), mb->end - checksum_pos)
    			  );

    mbuf_set_pos(mb, header_pos);
    return csock_next(&slot->csock, mb);
}

static struct csock *_receive_pkt( struct csock *source_cs
							     , struct mbuf *mb )
{
	if (!source_cs || !mb)
		return NULL;

	struct cd_relaymap_slot *slot = (struct cd_relaymap_slot *)source_cs;
	struct cd_relaymap *map = slot->map;

    size_t pfix = mb->pos;

#if 0
	re_printf( "GOT A PACKING _receive_pkt; %u\n\n%w\n\n"
             , mbuf_get_left(mb)
             , mbuf_buf(mb), mbuf_get_left(mb));
#endif

	if (mbuf_get_left(mb) < RELAYMAP_HEADER_LENGTH)
		return NULL;

	struct rmap_wireheader *wheader = (struct rmap_wireheader *)mbuf_buf(mb);

    const uint64_t label = arch_betoh64(mbuf_read_u64(mb));
    const uint8_t cas_errs = mbuf_read_u8(mb);
    const uint8_t vals = mbuf_read_u8(mb);
    const uint16_t penalty = arch_betoh16(mbuf_read_u16(mb));

    (void)cas_errs;
    (void)vals;
    (void)penalty;

#if 0
    re_printf("label_be = %w\n", &label, 4);
    re_printf("cas_errs = %u\n", cas_errs);
    re_printf("vals = %u\n", vals);
    re_printf("penalty_be = %u\n", penalty);
#endif

    const uint32_t src_idx = (uint32_t)(slot - map->slots);
    uint32_t bits = label_bitsused_label(label);
    const uint32_t dest_idx = label_decompress(label, bits);
    const uint32_t src_bits = label_bitsused_number(src_idx);

#if 0
    re_printf("src_idx = %u\n", src_idx);
    re_printf("dest_idx = %u\n", dest_idx);
    re_printf("src_bits = %u\n", src_bits);
#endif

    RELAYMAP_ASSERT_TRUE(dest_idx < RELAYMAP_SLOT_MAX);
    RELAYMAP_ASSERT_TRUE(src_idx < RELAYMAP_SLOT_MAX);

    /* we now know where our current header and content are */
    /* so, set accordingly... */

    mbuf_set_pos(mb, pfix);

    if (1 == dest_idx && 1 != (label & 0xf)) {
        debug(" 1 == dest_idx && 1 != (label & 0xf) \n");
        return _send_err(slot, mb, CTRL_ECODE_MALFORMED_ADDRESS);
    }

    if (src_bits > bits) {
        if (dest_idx == 1) {
            if (0 != ((label ^ 1) & (UINT64_MAX >> (64 - src_bits - 4)))) {
                return _send_err(slot, mb, CTRL_ECODE_RETURN_PATH_INVALID);
            }
            bits = src_bits;
        } else if (1 == src_idx) {
            if (0 != label >> (bits + 64 - src_bits)) {
                return _send_err(slot, mb, CTRL_ECODE_MALFORMED_ADDRESS);
            }
        } else {
            return _send_err(slot, mb, CTRL_ECODE_MALFORMED_ADDRESS);
        }
    }

    if (map->slots[dest_idx].state == RELAYMAP_SLOT_STATE_WIPE) {
    	return _send_err(slot, mb, CTRL_ECODE_MALFORMED_ADDRESS);
    }

    if (map->slots[dest_idx].state == RELAYMAP_SLOT_STATE_DOWN &&
        1 != src_idx)
    {
    	return _send_err(slot, mb, CTRL_ECODE_UNDELIVERABLE);
    }

    uint64_t src_label = reverse_b64(label_compressed(src_idx, bits));
    uint64_t target_label = (label >> bits) | src_label;

    /* update header! */
    wheader->label_be = arch_htobe64(target_label);
    uint32_t lshift = _wireheader_getshift(wheader) + bits;
    if (lshift > 63) { return NULL; } /* horizon'd ? */
    _wireheader_setshift(wheader, lshift);
    if (src_idx != 1 && dest_idx != 1) {
        debug("_do_penalty(source_cs->penalty, wheader, );\n");
    }

    debug("csock_next(&map->slots[dest_idx].csock, mb);\n");

    /* on ye go */
	return csock_next(&map->slots[dest_idx].csock, mb);
}

/* pinger */

void cd_relaymap_slot_setstate( struct cd_relaymap_slot *slot
						      , enum RELAYMAP_SLOT_STATE state )
{
	if (!slot || state > RELAYMAP_SLOT_STATE_CEIL) return;
	slot->state = state;
}

int cd_relaymap_slot_add( uint64_t *out_label
					    , struct cd_relaymap *map
				    	, struct csock *csock )
{
	uint8_t slotidx = 0;

	if (!map || !out_label || !csock)
		return EINVAL;

    for (;;slotidx++) {
        if (map->slots[slotidx].state == RELAYMAP_SLOT_STATE_WIPE) { break; }
        if (slotidx == RELAYMAP_SLOT_MAX) { return ENOMEM; }
    }

    struct cd_relaymap_slot *new_cs = &map->slots[ slotidx ];
    memset(new_cs, 0, sizeof(struct cd_relaymap_slot));
    new_cs->csock.send = _receive_pkt;
    /*newIf->penalty = Penalty_new(alloc, core->eventBase, core->logger);*/
    new_cs->state = RELAYMAP_SLOT_STATE_ISUP;

    new_cs->map = map;

    csock_flow(csock, &new_cs->csock);

    uint32_t bits = label_bitsused_number( slotidx );
    *out_label = label_compressed(slotidx, bits) | (1 << bits);

    /*debug("ASSIGNING: %u [%W]", slotidx, out_label, 8);*/

	return 0;
}

static void cd_relaymap_destructor(void *data)
{
	struct cd_relaymap *r = data;
	(void)r;
}

int cd_relaymap_init( struct cd_relaymap **relaymapp )
{
	struct cd_relaymap *map;

	if (!relaymapp)
		return EINVAL;

	map = mem_zalloc(sizeof(*map), cd_relaymap_destructor);
	if (!map)
		return ENOMEM;

    struct cd_relaymap_slot *router_cs = &map->slots[1];
    router_cs->csock.send = _receive_pkt;
    router_cs->state = RELAYMAP_SLOT_STATE_ISUP; /* router is always online */
    router_cs->map = map;
    map->router_cs = (struct csock *)&map->slots[1];

	*relaymapp = map;

	return 0;
}
