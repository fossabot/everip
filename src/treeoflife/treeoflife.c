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

#include <stdlib.h> /* abs */

static void treeoflife_dht_search_or_notify( struct treeoflife *t
										   , struct treeoflife_zone *z
										   , uint8_t dokey[KEY_LENGTH]
										   , bool do_search);

struct _binrep {
	uint8_t l;
	uint8_t *d;
};

static int bits_diff(const uint8_t *L, const uint8_t *R, int binlen)
{
	int i, score;
	for (i = 0; i < binlen; ++i) {
		if (b_val(L, i) != b_val(R, i)) {
			break;
		}
	}
	if (i == binlen) {
		return 0;
	}
	return binlen - i;
}

static int xor_diff(const uint8_t *L, const uint8_t *R, int len)
{
    int i, j;
    uint8_t xor;
    for(i = 0; i < len; i++) {
        if(L[i] != R[i])
            break;
    }

    if(i == len)
        return len*8;

    xor = L[i] ^ R[i];

    j = 0;
    while((xor & 0x80) == 0) {
        xor <<= 1;
        j++;
    }

    return (8 * i + j);
}

static int _util_print_debug(struct re_printf *pf, const struct _binrep *br)
{
	int err = 0;
	for (int i = 0; i < br->l; ++i) {
		err |= re_hprintf(pf, "%u", b_val(br->d, i));
	}
	return err;
}

static int slide_splice( uint8_t new_slide[ROUTE_LENGTH]
					   , uint8_t base_nbits
					   , const uint8_t *base_slide
					   , uint8_t next_nbits
					   , const uint8_t next_slide[2]
					   , uint8_t *new_bits )
{
	*new_bits = 0;

	if (!new_slide || !next_slide) {
		return EINVAL;
	}

	memset(new_slide, 0, ROUTE_LENGTH);

	/* first write base slide to new slide */
	debug("1BEFORE: %W\n", new_slide, ROUTE_LENGTH);
	for (int i = 0; i < base_nbits; ++i)
	{
		b_assign(new_slide, i, b_val(base_slide, i));
	}
	debug("1AFTER : %W\n", new_slide, ROUTE_LENGTH);

	/* next write next slide to new slide */
	debug("2BEFORE: %W\n", new_slide, ROUTE_LENGTH);
	for (int i = 0; i < next_nbits; ++i)
	{
		b_assign(new_slide, base_nbits+i, b_val(next_slide, i));
	}
	debug("2AFTER : %W\n", new_slide, ROUTE_LENGTH);
	*new_bits = base_nbits + next_nbits;

	debug("BITSBITS : %u\n", *new_bits);

	return 0;
}

static void treeoflife_dht_item_tmr(void *data)
{
	struct treeoflife_dht_item *dhti = data;
	dhti = mem_deref(dhti);
}
static void treeoflife_dht_item_destructor(void *data)
{
	struct treeoflife_dht_item *dhti = data;
	tmr_cancel(&dhti->tmr);
	list_unlink(&dhti->le);
}

static struct treeoflife_dht_item *treeoflife_dht_find( struct treeoflife *t
													  , uint8_t search_key[KEY_LENGTH] )
{
	struct le *le;
    struct treeoflife_dht_item *dhti = NULL;

    LIST_FOREACH(&t->dht_items, le) {
        dhti = le->data;
        if (!memcmp(dhti->key, search_key, KEY_LENGTH)) {
        	return dhti;
        }
    }
    return NULL;
}

static void treeoflife_node_destructor(void *data)
{
	struct treeoflife_node *tn = data;
	struct treeoflife_dht_item *dhti = NULL;
	tn->tree->children_ts = tmr_jiffies();

	for (int j = 0; j < ZONE_COUNT; ++j) {
		if (tn->tree->zone[j].parent == tn) {
			tn->tree->zone[j].parent = NULL;
			tn->tree->zone[j].height = 0;
			memcpy(tn->tree->zone[j].root, tn->tree->selfkey, KEY_LENGTH);

			/* flush dht table */
			list_flush(&tn->tree->dht_items);
		} else {
			dhti = treeoflife_dht_find(tn->tree, tn->key);
			if (dhti) {
				dhti = mem_deref(dhti);
			}
		}
	}
	for (int i = 0; i < ZONE_COUNT; ++i)
	{
		list_unlink(&tn->le[i]);
	}
	if (tn->peer) {
		tn->peer->tn = NULL;
	}
}


bool treeoflife_search( struct treeoflife *t
					  , uint8_t search_key[KEY_LENGTH]
					  , uint8_t *binlen
					  , uint8_t binrep[ROUTE_LENGTH] )
{
	struct le *le;
	struct treeoflife_zone *zone;
    struct treeoflife_node *tn = NULL;
    struct treeoflife_dht_item *dhti = NULL;

	if (!t)
		return false;

	/*debug("treeoflife_search\n");*/

	/* first, do a quick search to see if we match 1 hop chain network */
	for (int i = 0; i < ZONE_COUNT; ++i)
	{
		zone = &t->zone[i];

		/* how about our parent? */
		if (zone->parent && !memcmp(zone->parent->key, search_key, KEY_LENGTH)) {
			/*debug("treeoflife_search HOT PARENT\n");*/
        	*binlen = zone->parent->binlen;
        	memcpy(binrep, zone->parent->binrep, (((zone->parent->binlen + 7) & ~0x07)>>3) );
			return true;
		}

	    LIST_FOREACH(&t->zone[i].children, le) {
	        tn = le->data;
	        if (!memcmp(tn->key, search_key, KEY_LENGTH)) {
	        	/*debug("treeoflife_search HOT CHILD\n");*/
	        	*binlen = tn->binlen;
	        	memcpy(binrep, tn->binrep, (((tn->binlen + 7) & ~0x07)>>3) );
	        	return true;
	        }
	    }
	}

	/* next check dht */
	dhti = treeoflife_dht_find(t, search_key);

	if (dhti && !dhti->searching) {
    	*binlen = dhti->binlen;
    	memcpy(binrep, dhti->binrep, (((dhti->binlen + 7) & ~0x07)>>3) );
    	return true;
	}

	if (!dhti) {
		dhti = mem_zalloc(sizeof(*dhti), treeoflife_dht_item_destructor);
		if (!dhti) /* memory problems? */
			return false;
		tmr_init(&dhti->tmr);
		list_append(&t->dht_items, &dhti->le, dhti);
		memcpy(dhti->key, search_key, KEY_LENGTH);
		dhti->searching = 1;
		treeoflife_dht_search_or_notify(t, &t->zone[0], search_key, true);
		/* wait for 5 seconds */
		tmr_start(&dhti->tmr, 1000 * 5, treeoflife_dht_item_tmr, dhti);
	}

	return false;
}

struct treeoflife_peer *treeoflife_route_to_peer( struct treeoflife *t
												, uint8_t routelen
												, uint8_t route[ROUTE_LENGTH] )
{
	struct le *le;
	struct treeoflife_zone *zone;
    struct treeoflife_node *tn = NULL;

    struct treeoflife_node *tn_chosen = NULL;

	int local_diff, parent_diff, temp_diff, chosen_diff;

	for (int i = 0; i < ZONE_COUNT; ++i)
	{
		zone = &t->zone[i];

		local_diff = abs(routelen - zone->binlen) + bits_diff( route
							 , zone->binrep
							 , arch_max(routelen, zone->binlen) );

		debug("LOCAL DIFF = %d\n", local_diff);

		/* how about our parent? */
		if (zone->parent) {
			parent_diff = abs(routelen - zone->parent->binlen) + bits_diff( route
							 , zone->parent->binrep
							 , arch_max(routelen, zone->parent->binlen) );
			debug("PARENT DIFF = %d\n", parent_diff);
			if (routelen == zone->parent->binlen && parent_diff == 0) {
				tn_chosen = zone->parent;
				goto instant_hit;
			}
			if (parent_diff < local_diff) {
		        if (!tn_chosen || parent_diff < chosen_diff) {
		        	tn_chosen = zone->parent;
		        	chosen_diff = parent_diff;
		        }
			}
		}

	    LIST_FOREACH(&t->zone[i].children, le) {
	        tn = le->data;
			temp_diff = abs(routelen - tn->binlen) + bits_diff( route
							 , tn->binrep
							 , arch_max(routelen, tn->binlen) );
			debug("TEMP DIFF = %d\n", temp_diff);
			if (routelen == tn->binlen && temp_diff == 0) {
				tn_chosen = tn;
				goto instant_hit;
			}
			if (temp_diff < local_diff) {
		        if (!tn_chosen || temp_diff < chosen_diff) {
		        	tn_chosen = tn;
		        	chosen_diff = temp_diff;
		        }
			}
	    }
	}

instant_hit:
	if (tn_chosen && tn_chosen->peer) {
		return tn_chosen->peer;
	}

	return NULL;
}

static void treeoflife_dht_add_or_update( struct treeoflife *t
										, uint8_t dhtkey[KEY_LENGTH]
										, uint8_t binlen
										, uint8_t binrep[ROUTE_LENGTH]
										, bool searching)
{
	struct le *le;
	struct treeoflife_dht_item *dhti = NULL;

	dhti = treeoflife_dht_find(t, dhtkey);

	if (!dhti) {/* create a new entry */
		dhti = mem_zalloc(sizeof(*dhti), treeoflife_dht_item_destructor);
		if (!dhti)
			return;
		tmr_init(&dhti->tmr);
		list_append(&t->dht_items, &dhti->le, dhti);
	}

	if (dhti) {
    	/* we have it, so update*/
    	dhti->binlen = binlen;
    	memcpy(dhti->binrep, binrep, ROUTE_LENGTH);
    	memcpy(dhti->key, dhtkey, KEY_LENGTH);
    	dhti->searching = searching;
    	/* only lives for 10 minutes */
    	tmr_start(&dhti->tmr, (searching ? 5000 : 1000 * 60 * 10), treeoflife_dht_item_tmr, dhti);
	}

	return;
}

static void treeoflife_dht_search_or_notify( struct treeoflife *t
										   , struct treeoflife_zone *z
										   , uint8_t dokey[KEY_LENGTH]
										   , bool do_search)
{
	uint8_t selfkey[KEY_LENGTH];
	uint8_t binrep[ROUTE_LENGTH];
	struct treeoflife_peer *dst_peer;

	debug("treeoflife_dht_notify\n");

	/* copy the last 64 bits of the hash and then swap the order */
	memcpy(selfkey, dokey+KEY_LENGTH-8, 8);
	debug("BEFORE [%W]\n", selfkey, 8);
	*(uint64_t *)(void *)selfkey = reverse_b64(*(uint64_t *)(void *)selfkey);
	debug("AFTER [%W]\n", selfkey, 8);

	b_clr(selfkey, 0);

	/* here, we need to route a message to all nodes on the path set by our hash */
	dst_peer = treeoflife_route_to_peer(t, 64, selfkey);

	if (!dst_peer) {
		/* unlikely, but I guess we are not connected to anyone? */
		return;
	}

	memset(binrep, 0, ROUTE_LENGTH);
	memcpy(binrep, selfkey, 8);

	struct mbuf *mb = mbuf_alloc(640);

	/*(2+KEY_LENGTH+1+ROUTE_LENGTH+1+ROUTE_LENGTH)*/

    mbuf_write_u16(mb, arch_htobe16(TYPE_BASE+(do_search ? 3 : 2))); /* DHT STORE */
    mbuf_write_mem(mb, t->selfkey, KEY_LENGTH);

    /* DST */
    mbuf_write_u8(mb, 64);
    mbuf_write_mem(mb, binrep, ROUTE_LENGTH);

	/* SRC */
    mbuf_write_u8(mb, t->zone[0].binlen);
    mbuf_write_mem(mb, t->zone[0].binrep, ROUTE_LENGTH);

    /* write search key */
    mbuf_write_mem(mb, dokey, KEY_LENGTH);

    mbuf_set_pos(mb, 0);

	/*debug("ATTEMPTING SEND: [%W];\n", mbuf_buf(mb), mbuf_get_left(mb));*/

    if (t->cb)
    	t->cb(t, dst_peer, mb);

    mb = mem_deref(mb);


	return;
}

static void treeoflife_children_notify(struct treeoflife *t, struct treeoflife_zone *z)
{
	struct le *le;
	struct mbuf *mb_clone;
	struct treeoflife_zone *zone;
	struct treeoflife_node *tn = NULL;
	uint8_t new_slide[ROUTE_LENGTH];

	/*debug("treeoflife_children_notify\n");*/

	struct mbuf *mb = mbuf_alloc(640);

	mbuf_write_u16(mb, arch_htobe16((TYPE_BASE+1))); /* type 1 = coord */
	mbuf_write_mem(mb, t->selfkey, KEY_LENGTH);

    uint32_t children_len = 0;
    size_t top_pos = mb->pos;

	for (int i = 0; i < ZONE_COUNT; ++i)
	{
		zone = &t->zone[i];
		if (z && zone != z)
			continue;

		children_len = 0;
		LIST_FOREACH(&t->zone[i].children, le) {children_len++;}
	    if (!children_len)
	    	continue;

		mbuf_set_pos(mb, top_pos);

		mbuf_write_u8(mb, i); /* zone id */
		mbuf_write_u8(mb, zone->binlen);
		mbuf_write_mem(mb, zone->binrep, (((zone->binlen + 7) & ~0x07)>>3) );

	    uint32_t j = 0;
	    uint32_t bi = 0;
	    LIST_FOREACH(&t->zone[i].children, le) {
	        tn = le->data;
	        mb_clone = mbuf_clone(mb);

	        bi = j;
	        tn->binlen = 0;
	        if (j == 0) {
	        	tn->binlen = 1; /* we still need to represent that there was one node */
	        	*(uint16_t*)(void *)tn->binrep = 0;
	        } else {
		        while (bi) {tn->binlen++;bi>>=1;}
		        *(uint16_t*)(void *)tn->binrep = j;
	        }

			slide_splice( new_slide
						, zone->binlen
						, zone->binrep
					    , tn->binlen
					    , tn->binrep
					    , &tn->binlen );

			mbuf_write_u8(mb_clone, tn->binlen);
			mbuf_write_mem(mb_clone, (uint8_t *)&tn->binrep, (((tn->binlen + 7) & ~0x07)>>3) );

			mbuf_set_pos(mb_clone, 0);
			if (t->cb) {
				t->cb(t, tn->peer, mb_clone);
			}
			mb_clone = mem_deref(mb_clone);
			i++;
	    }
	}
    mb = mem_deref(mb);
	return;
}

void treeoflife_msg_recv( struct treeoflife *t
						, struct treeoflife_peer *peer
						, struct mbuf *mb
						, uint16_t weight )
{
	struct le *le;
	struct _binrep br;
	struct mbuf *mb_clone;
	struct treeoflife_peer *_p;
	size_t pos_top;
	struct treeoflife_zone *zone;
	struct treeoflife_node *tn = NULL;
	struct treeoflife_dht_item *dhti = NULL;

	struct treeoflife_peer *dst_peer;

	if (!t) return;

	pos_top = mb->pos;

	uint16_t type = arch_betoh16(mbuf_read_u16(mb));
	uint8_t sentkey[KEY_LENGTH];
	mbuf_read_mem(mb, sentkey, KEY_LENGTH);

	if (!memcmp(sentkey, t->selfkey, KEY_LENGTH)) {
		/*from ourselves? ignore. */
		return;
	}

	debug("GOT TYPE = %u from %W\n", type, sentkey, KEY_LENGTH);

	if (!peer->tn) {
		/* search */

		LIST_FOREACH(&t->peers, le) {
			_p = le->data;
			if (!_p->tn) continue;
			if (0 == memcmp(_p->tn->key, sentkey, KEY_LENGTH)) {
				return; /* could be an attack? */
			}
		}

		peer->tn = mem_zalloc(sizeof(*tn), treeoflife_node_destructor);
		if (!peer->tn) {
			goto err;
		}
		peer->tn->tree = t;
		peer->tn->peer = peer;
		memcpy(peer->tn->key, sentkey, KEY_LENGTH);
	}

	if (type == (TYPE_BASE+0)) { /* tree */
#if 1
		uint8_t tmp_root[KEY_LENGTH];
		uint16_t tmp_height;
		uint8_t tmp_parent[KEY_LENGTH];
		bool we_are_set_parent;
		int rootcmp;

		for (int i = 0; i < ZONE_COUNT; ++i)
		{
			zone = &t->zone[i];
			mbuf_read_mem(mb, tmp_root, KEY_LENGTH);
			tmp_height = arch_betoh16(mbuf_read_u16(mb));
			mbuf_read_mem(mb, tmp_parent, KEY_LENGTH);
			we_are_set_parent = !memcmp(tmp_parent, t->selfkey, KEY_LENGTH);

			rootcmp = memcmp(tmp_root, zone->root, KEY_LENGTH);

			if (!we_are_set_parent
				&& (rootcmp > 0) ) /*|| (!rootcmp && tmp_height + weight < zone->height)*/
			{
				/* zone kanri */
				memcpy(zone->root, tmp_root, KEY_LENGTH);
				zone->height = tmp_height + weight;
				zone->parent = peer->tn;
			}

		    LIST_FOREACH(&t->zone[i].children, le) {
		        tn = le->data;
		        if (0 == memcmp(tn->key, sentkey, KEY_LENGTH)) {
		        	break;
		        } else {
		        	tn = NULL;
		        }
		    }

			if (!tn && we_are_set_parent) {
				/* we are the parent of this node */
				list_append(&t->zone[i].children, &peer->tn->le[i], peer->tn);
				t->children_ts = tmr_jiffies();
			}

			if (tn && !we_are_set_parent) {
				list_unlink(&tn->le[i]);
				/*t->children_ts = tmr_jiffies();*/
			}

		}
#endif

		return;
	} else if (type == (TYPE_BASE+1)) { /* coord + we have to think that they are our parents! */
		uint8_t tmp_zoneid;
		if (!mbuf_get_left(mb)) {
			goto err;
		}
		tmp_zoneid = mbuf_read_u8(mb);
		if (tmp_zoneid > ZONE_COUNT-1) {
			goto err;
		}

		zone = &t->zone[ tmp_zoneid ];

		/* check to make sure we're the parent */
		if (zone->parent != peer->tn) {
			goto err;
		}

		if (mbuf_get_left(mb) < 1) {
			goto err;
		}

		/*debug("LENGTH: %u DATA[%W]\n", mbuf_get_left(mb), mb->buf, mb->size);*/

		uint8_t tmp_pzbinlen = mbuf_read_u8(mb);
		uint8_t tmp_pzbinrep[ROUTE_LENGTH];
		if ( (((tmp_pzbinlen + 7) & ~0x07)>>3) > ROUTE_LENGTH ) {
			goto err;
		}
		mbuf_read_mem(mb, tmp_pzbinrep, (((tmp_pzbinlen + 7) & ~0x07)>>3));

	    br.l = tmp_pzbinlen;
	    br.d = (uint8_t *)tmp_pzbinrep;
	    debug("ZONE[%u]BINREP[%H]\n", tmp_zoneid, _util_print_debug, &br);

		uint8_t tmp_zbinlen = mbuf_read_u8(mb);
		uint8_t tmp_zbinrep[ROUTE_LENGTH];
		if ( (((tmp_zbinlen + 7) & ~0x07)>>3) > ROUTE_LENGTH ) {
			goto err;
		}
		mbuf_read_mem(mb, tmp_zbinrep, (((tmp_zbinlen + 7) & ~0x07)>>3));
	    br.l = tmp_zbinlen;
	    br.d = (uint8_t *)tmp_zbinrep;
	    debug("MY BINREP[%H]\n", _util_print_debug, &br);

	    /* copy parent */
	    zone->parent->binlen = tmp_pzbinlen;
		memcpy(zone->parent->binrep, tmp_pzbinrep, (((tmp_pzbinlen + 7) & ~0x07)>>3) );

		/* copy us */
	    zone->binlen = tmp_zbinlen;
		memcpy(zone->binrep, tmp_zbinrep, (((tmp_zbinlen + 7) & ~0x07)>>3) );

		treeoflife_dht_search_or_notify(t, zone, t->selfkey, false);

		treeoflife_children_notify(t, zone);

		return;
	} else if (type == (TYPE_BASE+2) || type == (TYPE_BASE+3) || type == (TYPE_BASE+4)) {
		/* DHT STORE / RETRIEVE ANSWER */
		if (mbuf_get_left(mb) < 2 + (ROUTE_LENGTH*2)) {
			goto err;
		}

		uint8_t dst_binlen = mbuf_read_u8(mb);
		uint8_t dst_binrep[ROUTE_LENGTH];
		mbuf_read_mem(mb, dst_binrep, ROUTE_LENGTH);

		uint8_t src_binlen = mbuf_read_u8(mb);
		uint8_t src_binrep[ROUTE_LENGTH];
		mbuf_read_mem(mb, src_binrep, ROUTE_LENGTH);

		uint8_t dhtkey[ROUTE_LENGTH];
		mbuf_read_mem(mb, dhtkey, KEY_LENGTH);

		debug("GOT DHT STORE/RETRIEVE REQUEST FOR [%W];\n", dhtkey, KEY_LENGTH);
	    br.l = dst_binlen;
	    br.d = (uint8_t *)dst_binrep;
	    debug("DST:BINREP[%u][%H]\n", dst_binlen, _util_print_debug, &br);

	    int _diff = bits_diff( dst_binrep
			 , t->zone[0].binrep
			 , arch_max(dst_binlen, t->zone[0].binlen));

	    if (type == (TYPE_BASE+4)) {
			uint8_t ans_binlen = mbuf_read_u8(mb);
			uint8_t ans_binrep[ROUTE_LENGTH];
			mbuf_read_mem(mb, ans_binrep, ROUTE_LENGTH);

		    br.l = ans_binlen;
		    br.d = (uint8_t *)ans_binrep;
		    debug("ANSWER:BINREP[%u][%H]\n", ans_binlen, _util_print_debug, &br);

		    if (t->zone[0].binlen == dst_binlen
		    	&& 0 == _diff) {
		    	return; /* cool, we end here !*/
		    }
			goto dht_redirect;
		    return; /* UNREACHABLE */
	    }

	    dhti = treeoflife_dht_find(t, dhtkey);

		if (type == (TYPE_BASE+3)) {
			debug("TYPE_BASE+3 %p\n", dhti);
			if (dhti) {
				/* cool, we have what you are looking for! */
				mb_clone = mbuf_alloc(272);
				mbuf_set_pos(mb_clone, 0);
			    mbuf_write_u16(mb_clone, arch_htobe16((TYPE_BASE+4))); /* DHT ANSWER */
			    mbuf_write_mem(mb_clone, t->selfkey, KEY_LENGTH);

			    /* DST */
			    mbuf_write_u8(mb_clone, src_binlen);
			    mbuf_write_mem(mb_clone, src_binrep, ROUTE_LENGTH);

				/* SRC */
			    mbuf_write_u8(mb_clone, t->zone[0].binlen);
			    mbuf_write_mem(mb_clone, t->zone[0].binrep, ROUTE_LENGTH);

			    mbuf_write_mem(mb_clone, dhti->key, KEY_LENGTH);
			    mbuf_write_u8(mb_clone, dhti->binlen);
			    mbuf_write_mem(mb_clone, dhti->binrep, ROUTE_LENGTH);
			    /* X:TODO, we should have this signed! */

			    dst_peer = treeoflife_route_to_peer(t, src_binlen, src_binrep);
			    if (dst_peer && t->cb) {
					/* bombs away! */
					mbuf_set_pos(mb_clone, 0);
			    	t->cb(t, dst_peer, mb_clone);
			    }
				mb_clone = mem_deref(mb_clone);
			}
		} else { /* STORAGE */
			if (!dhti) {/* create a new entry */
				dhti = mem_zalloc(sizeof(*dhti), treeoflife_dht_item_destructor);
				if (!dhti)
					goto err;
				tmr_init(&dhti->tmr);
				list_append(&t->dht_items, &dhti->le, dhti);
			}

			if (dhti) {
	        	/* we have it, so update*/
	        	dhti->binlen = src_binlen;
	        	memcpy(dhti->binrep, src_binrep, ROUTE_LENGTH);
	        	memcpy(dhti->key, dhtkey, KEY_LENGTH);
	        	dhti->searching = false;
	        	/* only lives for 10 minutes */
	        	tmr_start(&dhti->tmr, 1000 * 60 * 10, treeoflife_dht_item_tmr, dhti);
			}
		}

	    if (t->zone[0].binlen == dst_binlen
	    	&& 0 == _diff) {
	    	return; /* cool, we end here !*/
	    }

dht_redirect:

		debug("STILL NEED TO REDIRECT DHT\n");
		dst_peer = treeoflife_route_to_peer(t, dst_binlen, dst_binrep);

		if (!dst_peer) {
			debug("DHT;; GUESS IT STOPS WITH US!\n");
			return;
		}

		/* bombs away! */
		mbuf_set_pos(mb, pos_top);

	    if (t->cb)
	    	t->cb(t, dst_peer, mb);

	    return;

	} else if (type < TYPE_BASE) {
		/* hello, mr ipv6! */
		/*[DST_BINLEN(1)][DST_BINROUTE(ROUTE_LENGTH)][SRC_BINLEN(1)][SRC_BINROUTE(ROUTE_LENGTH)]*/

		if (mbuf_get_left(mb) < 2 + (ROUTE_LENGTH*2)) {
			goto err;
		}

		uint8_t dst_binlen = mbuf_read_u8(mb);
		uint8_t dst_binrep[ROUTE_LENGTH];
		mbuf_read_mem(mb, dst_binrep, ROUTE_LENGTH);

		uint8_t src_binlen = mbuf_read_u8(mb);
		uint8_t src_binrep[ROUTE_LENGTH];
		mbuf_read_mem(mb, src_binrep, ROUTE_LENGTH);

	    /*br.l = src_binlen;
	    br.d = (uint8_t *)src_binrep;*/
	    /*debug("SRC:BINREP[%u][%H]\n", src_binlen, _util_print_debug, &br);*/

	    /*br.l = dst_binlen;
	    br.d = (uint8_t *)dst_binrep;*/
	    /*debug("DST:BINREP[%u][%H]\n", dst_binlen, _util_print_debug, &br);*/

	    /*br.l = t->zone[0].binlen;
	    br.d = (uint8_t *)t->zone[0].binrep;*/
	    /*debug("MYY:BINREP[%u][%H]\n", dst_binlen, _util_print_debug, &br);*/

	    int _diff = bits_diff( dst_binrep
			 , t->zone[0].binrep
			 , arch_max(dst_binlen, t->zone[0].binlen));

	    /*debug("GOT DIFF OF %d\n", _diff);*/

		treeoflife_dht_add_or_update( t
									, sentkey
									, src_binlen
									, src_binrep
									, false);


	    if (t->zone[0].binlen == dst_binlen
	    	&& 0 == _diff) {
	    	/*debug("HEY THIS IS US!\n");*/
	    	goto process_pkt;
	    }

	    debug("NEED TO REDIRECT!\n");
		dst_peer = treeoflife_route_to_peer(t, dst_binlen, dst_binrep);
		if (!dst_peer) {
			return;
		}

		/* bombs away! */
		mbuf_set_pos(mb, pos_top);

	    if (t->cb)
	    	t->cb(t, dst_peer, mb);

	    return;

process_pkt:
		if (t->tun_cb) {
			mbuf_advance(mb, -(WIRE_IPV6_HEADER_LENGTH));
		    struct _wire_ipv6_header *ihdr = \
		        (struct _wire_ipv6_header *)mbuf_buf(mb);

	        memset(ihdr, 0, WIRE_IPV6_HEADER_LENGTH - 32);

		    ((uint8_t*)ihdr)[0] |= (6) << 4;
		    ihdr->hop = 42;
		    ihdr->next_header = type;
		    ihdr->payload_be = arch_htobe16(mbuf_get_left(mb) - WIRE_IPV6_HEADER_LENGTH);

		    ihdr->src[0] = 0xFC;
		    ihdr->dst[0] = 0xFC;
			memcpy(ihdr->src+1, sentkey, KEY_LENGTH);
		    memcpy(ihdr->dst+1, t->selfkey, KEY_LENGTH);

		    mbuf_advance(mb, -4);
		    ((uint16_t*)(void *)mbuf_buf(mb))[0] = 0;
		    ((uint16_t*)(void *)mbuf_buf(mb))[1] = 7680;

		    t->tun_cb(t, mb);
		}


#if 0
		uint8_t hop;
		uint8_t ipv6_src[KEY_LENGTH+1];
		uint8_t ipv6_dst[KEY_LENGTH+1];
		ipv6_src[0] = 0xFC;
		ipv6_dst[0] = 0xFC;

		hop = mbuf_read_u8(mb);
		mbuf_read_mem(mb, ipv6_src+1, KEY_LENGTH);
		mbuf_read_mem(mb, ipv6_dst+1, KEY_LENGTH);

		if (memcmp(ipv6_dst+1, t->selfkey, KEY_LENGTH)) {
			/* not us */
			mbuf_set_pos(mb, pos_top);
			treeoflife_search(t, sentkey, ipv6_src+1, ipv6_dst+1, mb);
			return;
		}

#endif
		return;
	} else {
		error("unknown type %u\n", type);
	}
err:
	return;
}

void treeoflife_register_cb( struct treeoflife *t
						   , treeoflife_treemsg_h *cb)
{
	if (!t) return;
	t->cb = cb;
}

void treeoflife_register_tuncb( struct treeoflife *t
						   , treeoflife_tunnel_h *cb)
{
	if (!t) return;
	t->tun_cb = cb;
}

static void _tmr_maintain_cb(void *data)
{
	struct treeoflife *t = data;
	uint64_t now = tmr_jiffies();
/*	debug("now - t->children_ts == %u", now - t->children_ts);
*/	/*debug("\n\n====================\n%H\n====================\n\n", treeoflife_debug, t);*/

    if (t->children_ts < t->maintain_ts && (now - t->children_ts) < 50000) {
    	goto out;
    }
    t->children_ts = now - 1;
    debug("CHILDREN! %u\n", t->children_ts - t->maintain_ts);
    treeoflife_children_notify(t, NULL);
out:
	t->maintain_ts = now;
	tmr_start(&t->tmr_maintain, 3000 + ((uint8_t)rand_char()), _tmr_maintain_cb, t);
}

static void _tmr_cb(void *data)
{
	struct treeoflife *t = data;
	struct mbuf *mb = mbuf_alloc(272);
	const struct treeoflife_zone *zone;

#if 1
	mbuf_write_u16(mb, arch_htobe16((TYPE_BASE+0))); /* type 1 = tree */
	mbuf_write_mem(mb, t->selfkey, KEY_LENGTH);

	for (int i = 0; i < ZONE_COUNT; ++i)
	{
		zone = &t->zone[i];
		mbuf_write_mem(mb, zone->root, KEY_LENGTH);
		mbuf_write_u16(mb, arch_htobe16(zone->height));
		if (zone->parent) {
			mbuf_write_mem(mb, zone->parent->key, KEY_LENGTH);
		} else {
			mbuf_fill(mb, 0, KEY_LENGTH);
		}
	}

	mbuf_set_pos(mb, 0);

	if (t->cb)
		t->cb(t, NULL, mb);

#endif

	mb = mem_deref(mb);

	/* JUST FOR TESTING! */
	treeoflife_dht_search_or_notify(t, &t->zone[0], t->selfkey, false);

	tmr_start(&t->tmr, 2000 + ((uint8_t)rand_char()), _tmr_cb, t);
}

int treeoflife_debug(struct re_printf *pf, const struct treeoflife *t)
{
	int err = 0;
	struct le *le;
	const struct treeoflife_zone *zone;
	struct treeoflife_node *tn = NULL;

	struct _binrep br;

	if (!t)
		return 0;

	err |= re_hprintf(pf, "\nI AM: [%W]\n\n", t->selfkey, KEY_LENGTH);

	for (int i = 0; i < ZONE_COUNT; ++i)
	{
		zone = &t->zone[i];
		err |= re_hprintf(pf, "ZONE[%i][ROOT:%W][HEIGHT:%u]\n", i, &zone->root, KEY_LENGTH, zone->height);
		if (zone->parent) {
			err |= re_hprintf(pf, "  PARENT[%W@%J]\n", zone->parent->key, KEY_LENGTH, &zone->parent->peer->sa);
		    br.l = zone->parent->binlen;
		    br.d = (uint8_t *)zone->parent->binrep;
	        err |= re_hprintf(pf, "        [%u@%H]\n", zone->parent->binlen, _util_print_debug, &br);
		}
	    LIST_FOREACH(&zone->children, le) {
	        tn = le->data;
	        err |= re_hprintf(pf, "  CHILD[%W@%J]\n", tn->key, KEY_LENGTH, &tn->peer->sa);
		    br.l = tn->binlen;
		    br.d = (uint8_t *)tn->binrep;
	        err |= re_hprintf(pf, "  ROUTE[%u@%H]\n", tn->binlen, _util_print_debug, &br);
	    }
	    if (!zone->binlen) {
			err |= re_hprintf(pf, "  COORDS[ROOT]\n");
	    } else {
		    br.l = zone->binlen;
		    br.d = (uint8_t *)zone->binrep;
		    err |= re_hprintf(pf, "  COORDS[%u][%H]\n", zone->binlen, _util_print_debug, &br);
	    }
	}

	return err;
}

int treeoflife_dht_debug(struct re_printf *pf, const struct treeoflife *t)
{
	int err = 0;
	struct le *le;
	struct _binrep br;
	struct treeoflife_dht_item *dhti = NULL;

    LIST_FOREACH(&t->dht_items, le) {
        dhti = le->data;
	    br.l = dhti->binlen;
	    br.d = (uint8_t *)dhti->binrep;
        err |= re_hprintf(pf, "[%W][%u@%H]%s\n", dhti->key
        									   , KEY_LENGTH
        									   , dhti->binlen
        									   , _util_print_debug, &br
        									   , dhti->searching ? "SEARCHING" : "");
    }

    if (!dhti) {
    	err |= re_hprintf(pf, "NO ITEMS CURRENTLY STORED IN DHT\n");
    }

    return err;
}

static void treeoflife_destructor(void *data)
{
	struct treeoflife *t = data;
	for (int i = 0; i < ZONE_COUNT; ++i)
	{
		list_flush(&t->zone[i].children);
	}
	list_flush(&t->peers);
	list_flush(&t->dht_items);
	tmr_cancel(&t->tmr);
	tmr_cancel(&t->tmr_maintain);
}

int treeoflife_init( struct treeoflife **treeoflifep, uint8_t public_key[KEY_LENGTH] )
{
	int err = 0;
	struct treeoflife *t;

	if (!treeoflifep)
		return EINVAL;

	t = mem_zalloc(sizeof(*t), treeoflife_destructor);
	if (!t)
		return ENOMEM;

	for (int i = 0; i < ZONE_COUNT; ++i)
	{
		list_init(&t->zone[i].children);
		memcpy(t->zone[i].root, public_key, KEY_LENGTH);
		t->zone[i].binlen = 1;
	}

	memcpy(t->selfkey, public_key, KEY_LENGTH);



	tmr_init(&t->tmr);
	tmr_start(&t->tmr, 0, _tmr_cb, t);

	tmr_init(&t->tmr_maintain);
	tmr_start(&t->tmr_maintain, 0, _tmr_maintain_cb, t);

	*treeoflifep = t;

	if (err)
		t = mem_deref(t);
	return err;
}


static void peer_destructor(void *data)
{
	struct treeoflife_peer *p = data;
	list_unlink(&p->le);
	p->tn = mem_deref(p->tn);
	tmr_cancel(&p->tmr);
}

static void peer_timedout(void *data)
{
	struct treeoflife_peer *p = data;
	if (p->lock) return;
	p = mem_deref(p);
}

int treeoflife_peer_find_or_new( struct treeoflife_peer **pp
							   , struct treeoflife *t
							   , const struct sa *sa
							   , bool is_locked )
{
	int err = 0;
	struct treeoflife_peer *p;
	struct le *le;

	if (!t || !sa)
		return EINVAL;

	/* check to make sure we already do not have this peer */
	LIST_FOREACH(&t->peers, le) {
		p = le->data;
		if (sa_cmp(&p->sa, sa, SA_ALL)) {
			goto out;
		}
	}

	p = mem_zalloc(sizeof(*p), peer_destructor);
	if (!p)
		return ENOMEM;

	sa_cpy(&p->sa, sa);
	list_append(&t->peers, &p->le, p);

	tmr_init(&p->tmr);

	p->lock = is_locked;

out:
	if (pp) {
		*pp = p;
	}
	tmr_start(&p->tmr, 10000, peer_timedout, p);
	return err;
}
