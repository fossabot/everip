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

static struct mbuf *tol_mbuf_alloc(void)
{
  struct mbuf *mb = mbuf_alloc(EVER_OUTWARD_MBE_LENGTH*2);

  mb->pos = mb->size;
  mb->end = mb->size;

  return mb;
}

static void treeoflife_dht_search_or_notify( struct treeoflife *t
                       , struct treeoflife_zone *z
                       , uint8_t dokey[KEY_LENGTH]
                       , bool do_search);

struct _binrep {
  uint8_t l;
  uint8_t *d;
};

static uint8_t stack_height_get(const uint8_t *binrep)
{
    return binrep[0];
}

static void stack_height_set(uint8_t *binrep, uint8_t height)
{
    if (!height) return;
    binrep[0] = height;
}

static uint16_t stack_calc_size(uint8_t *binrep, uint8_t *height)
{
    int pos; /* size in bytes */
    uint8_t size;
    size = stack_height_get(binrep);
    if (height) *height = size;
    if (!size) return 1;
    pos = 1;
    while (size--) {
        if (binrep[pos] == 0xFE) { /* 11111110 */
            pos += 8;
        } else if ((binrep[pos] & 0xFE) == 0xFC) { /* 1111110x */
            pos += 7;
        } else if ((binrep[pos] & 0xFC) == 0xF8) { /* 111110xx */
            pos += 6;
        } else if ((binrep[pos] & 0xF8) == 0xF0) { /* 11110xxx */
            pos += 5;
        } else if ((binrep[pos] & 0xF0) == 0xE0) { /* 1110xxxx */
            pos += 4;
        } else if ((binrep[pos] & 0xE0) == 0xC0) { /* 110xxxxx */
            pos += 3;
        } else if ((binrep[pos] & 0xC0) == 0x80) { /* 10xxxxxx */
            pos += 2;
        } else if ((binrep[pos] & 0x80) == 0x00) { /* 0xxxxxxx */
            pos += 1; /* our data is included here */
        }
    }

    return pos;
}

static size_t stack_layer_add(uint8_t *binrep, uint64_t nodeid)
{
    size_t size;
    uint8_t height;
    size = stack_calc_size(binrep, &height);
    int layersize;
    uint8_t layer_data[8] = {0};

    /* calculate size of the slot that we want to create */

    if (nodeid <= 0x7f) {
        layer_data[0] = nodeid;
        layersize = 1;
    } else {
        return 0;
    }

    if (size + layersize > 128)
        return 0;

    memcpy(&binrep[size], layer_data, layersize);

    /* set new size header */
    stack_height_set(binrep, height + 1);

    return size + layersize;
}

struct stack_needle {
    int pos;
    uint8_t height;
    uint8_t start;
    uint8_t stop;
    uint8_t *binrep;
    int i;
    bool setup;
    bool inloop;
    bool end;
};

static int stack_step(struct stack_needle *needle)
{
    uint8_t b;
    if (needle->end) return 0;
    if (!needle->setup) {
        needle->setup = true;
        needle->height = stack_height_get(needle->binrep);
        if (!needle->height) {
            needle->end = true;
            return 0;
        }
        needle->pos = 1;
    }
    if (needle->inloop) {
        goto loop;
    }
    do {
        if (needle->binrep[needle->pos] == 0xFE) { /* 11111110 */
            needle->stop = 8;
        } else if ((needle->binrep[needle->pos] & 0xFE) == 0xFC) { /* 1111110x */
            needle->stop = 7;
        } else if ((needle->binrep[needle->pos] & 0xFC) == 0xF8) { /* 111110xx */
            needle->stop = 6;
        } else if ((needle->binrep[needle->pos] & 0xF8) == 0xF0) { /* 11110xxx */
            needle->stop = 5;
        } else if ((needle->binrep[needle->pos] & 0xF0) == 0xE0) { /* 1110xxxx */
            needle->stop = 4;
        } else if ((needle->binrep[needle->pos] & 0xE0) == 0xC0) { /* 110xxxxx */
            needle->stop = 3;
        } else if ((needle->binrep[needle->pos] & 0xC0) == 0x80) { /* 10xxxxxx */
            needle->stop = 2;
        } else if ((needle->binrep[needle->pos] & 0x80) == 0x00) { /* 0xxxxxxx */
            needle->stop = 1; /* our data is included here */
        }

        needle->start = 0;
        needle->inloop = true;
        needle->i = needle->stop;
loop:
        while (needle->i < (needle->stop*8)) {
            b = b_val(&(needle->binrep[needle->pos]), needle->i);
            /*debug("I=%u\n", i);*/
            if (!b && !needle->start && needle->i + 1 != (needle->stop * 8)) {
                ++needle->i;
                continue;
            }
            ++needle->i;
            needle->start = 1;
            return b ? needle->height : -1 * needle->height;
        };
        needle->inloop = false;
        needle->pos += needle->stop;

    } while (--needle->height);

    needle->end = true;

    return 0;
}

static int stack_linf_diff(uint8_t left[ROUTE_LENGTH], uint8_t right[ROUTE_LENGTH])
{
    int score = 0;
    int lval = 0;
    int rval = 0;
    struct stack_needle lneedle;
    struct stack_needle rneedle;

    memset(&lneedle, 0, sizeof(struct stack_needle));
    memset(&rneedle, 0, sizeof(struct stack_needle));

    lneedle.binrep = left;
    rneedle.binrep = right;

    lval = stack_step(&lneedle);
    rval = stack_step(&rneedle);
    score += abs(lval-rval);

    while (!lneedle.end && !rneedle.end ) {
        lval = stack_step(&lneedle);
        rval = stack_step(&rneedle);
        if (!lval || !rval) break;
        /*debug("lval = %d; rval = %d\n", lval, rval);*/
        score += abs(lval-rval);
    }
    return score;
}

static int stack_debug(struct re_printf *pf, const uint8_t *binrep)
{
    int err = 0;

    int pos; /* size in bytes */
    uint8_t height, start, stop, b;
    height = stack_height_get(binrep);
    err |= re_hprintf(pf, "[H%u]", height);
    if (!height) return 0;
    pos = 1;
    do {
        err |= re_hprintf(pf, "[");
        if (binrep[pos] == 0xFE) { /* 11111110 */
            stop = 8;
        } else if ((binrep[pos] & 0xFE) == 0xFC) { /* 1111110x */
            stop = 7;
        } else if ((binrep[pos] & 0xFC) == 0xF8) { /* 111110xx */
            stop = 6;
        } else if ((binrep[pos] & 0xF8) == 0xF0) { /* 11110xxx */
            stop = 5;
        } else if ((binrep[pos] & 0xF0) == 0xE0) { /* 1110xxxx */
            stop = 4;
        } else if ((binrep[pos] & 0xE0) == 0xC0) { /* 110xxxxx */
            stop = 3;
        } else if ((binrep[pos] & 0xC0) == 0x80) { /* 10xxxxxx */
            stop = 2;
        } else if ((binrep[pos] & 0x80) == 0x00) { /* 0xxxxxxx */
            stop = 1; /* our data is included here */
        }

        start = 0;
        for (int i = stop; i < (stop*8); ++i) {
            b = b_val(&binrep[pos], i);
            /*debug("I=%u\n", i);*/
            if (!b && !start && i+1 != (stop*8)) continue;
            start = 1;
            err |= re_hprintf(pf, "%s%u", b ? "+" : "-", height);
        }

        err |= re_hprintf(pf, "]");

        pos += stop;

    } while (--height);

    return err;
}

#if 0
static int bits_diff(const uint8_t *L, const uint8_t *R, int binlen)
{
  int i;
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

static int bits_score(const uint8_t *L, const uint8_t *R, int binlen)
{
  int i, score = 0;
  for (i = 0; i < binlen; ++i) {
    if (b_val(L, i) != b_val(R, i)) {
      break;
    }
    if (!b_val(L, i)) {
      score--;
    } else {
      score++;
    }
  }
  return score;
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

    return ((8 * i) + j);
}
#endif

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
      /*slide_compress(0, tn->tree->zone[j].binrep, &tn->tree->zone[j].binlen);*/
      memset(tn->tree->zone[j].binrep, 0, ROUTE_LENGTH);
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
            , uint8_t *binrep/*[ROUTE_LENGTH]*/
            , bool skip_dht)
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
          memcpy(binrep, zone->parent->binrep, zone->parent->binlen);
      return true;
    }

      LIST_FOREACH(&t->zone[i].children, le) {
          tn = le->data;
          if (!memcmp(tn->key, search_key, KEY_LENGTH)) {
            /*debug("treeoflife_search HOT CHILD\n");*/
            *binlen = tn->binlen;
            memcpy(binrep, tn->binrep, tn->binlen);
            return true;
          }
      }
  }

if (!skip_dht) {
  /* next check dht */
  dhti = treeoflife_dht_find(t, search_key);

  if (dhti && !dhti->searching) {
      *binlen = dhti->binlen;
      memcpy(binrep, dhti->binrep, dhti->binlen);
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
}

  return false;
}

struct treeoflife_peer *treeoflife_route_to_peer( struct treeoflife *t
                        , uint8_t routelen
                        , uint8_t *route/*[ROUTE_LENGTH]*/ )
{

  struct le *le;
  struct treeoflife_zone *zone;
    struct treeoflife_node *tn = NULL;

    struct treeoflife_node *tn_chosen = NULL;

  int local_diff, parent_diff, temp_diff, chosen_diff;

  for (int i = 0; i < ZONE_COUNT; ++i)
  {
    zone = &t->zone[i];

    local_diff = stack_linf_diff(route, zone->binrep);

    debug("LOCAL DIFF = %d\n", local_diff);
    if (zone->parent) { /* how about our parent? */

      parent_diff = stack_linf_diff(route, zone->parent->binrep);

      debug("PARENT DIFF = %d\n", parent_diff);
      if (parent_diff < local_diff) {
            if (!tn_chosen || parent_diff < chosen_diff) {
              tn_chosen = zone->parent;
              chosen_diff = parent_diff;
            }
      }
    }

      LIST_FOREACH(&t->zone[i].children, le) {
          tn = le->data;

      temp_diff = stack_linf_diff(route, tn->binrep);
      debug("TEMP DIFF = %d\n", temp_diff);
      if (temp_diff < local_diff) {
            if (!tn_chosen || temp_diff < chosen_diff) {
              tn_chosen = tn;
              chosen_diff = temp_diff;
            }
      }
      }
  }

/*instant_hit:*/
  if (tn_chosen && tn_chosen->peer) {
    return tn_chosen->peer;
  }

  return NULL;
}

static void treeoflife_dht_add_or_update( struct treeoflife *t
                    , uint8_t dhtkey[KEY_LENGTH]
                    , uint8_t binlen
                    , uint8_t *binrep/*[ROUTE_LENGTH]*/
                    , bool searching)
{
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
  /*uint8_t searchkey[KEY_LENGTH];*/
  uint8_t binrep[ROUTE_LENGTH];
  struct treeoflife_peer *dst_peer;

  size_t pos;

  debug("treeoflife_dht_notify\n");

  /* copy the last 64 bits of the hash and then swap the order */
#if 0
  memcpy(searchkey, dokey+KEY_LENGTH-8, 8);
  debug("BEFORE [%W]\n", searchkey, 8);
  *(uint64_t *)(void *)searchkey = reverse_b64(*(uint64_t *)(void *)searchkey);
  debug("AFTER [%W]\n", searchkey, 8);
#endif

  memset(binrep, 0, ROUTE_LENGTH);

  /* here, we need to route a message to all nodes on the path set by our hash */
  dst_peer = treeoflife_route_to_peer(t, ROUTE_LENGTH, binrep);

  if (!dst_peer) {
    /* unlikely, but I guess we are not connected to anyone? */
    return;
  }


  struct mbuf *mb = tol_mbuf_alloc();

  /*(2+KEY_LENGTH+1+ROUTE_LENGTH+1+ROUTE_LENGTH)*/
  mbuf_advance(mb, -( 2
                    + KEY_LENGTH
                    + 1
                    + ROUTE_LENGTH
                    + 1
                    + ROUTE_LENGTH
                    + KEY_LENGTH));
  pos = mb->pos;

  mbuf_write_u16(mb, arch_htobe16(TYPE_BASE+(do_search ? 3 : 2))); /* DHT STORE */
  mbuf_write_mem(mb, t->selfkey, KEY_LENGTH);

  /* DST */
  mbuf_write_u8(mb, ROUTE_LENGTH);
  mbuf_write_mem(mb, binrep, ROUTE_LENGTH);

  /* SRC */
  mbuf_write_u8(mb, t->zone[0].binlen);
  mbuf_write_mem(mb, t->zone[0].binrep, ROUTE_LENGTH);

  /* write search key */
  mbuf_write_mem(mb, dokey, KEY_LENGTH);

  mbuf_set_pos(mb, pos);

  /*debug("ATTEMPTING SEND: [%W];\n", mbuf_buf(mb), mbuf_get_left(mb));*/

    if (t->cb)
      t->cb(t, dst_peer, mb, t->cb_arg);

    mb = mem_deref(mb);


  return;
}

static void treeoflife_children_notify(struct treeoflife *t, struct treeoflife_zone *z)
{
  struct le *le;
  size_t top_pos;
  struct mbuf *mb_clone;
  struct treeoflife_zone *zone;
  struct treeoflife_node *tn = NULL;

  /*debug("treeoflife_children_notify\n");*/

  struct mbuf *mb = tol_mbuf_alloc();

  mbuf_advance(mb, -( 2
                    + KEY_LENGTH
                    + 1
                    + 1
                    + ROUTE_LENGTH
                    + 1
                    + ROUTE_LENGTH));

  top_pos = mb->pos;

  mbuf_write_u16(mb, arch_htobe16((TYPE_BASE+1))); /* type 1 = coord */
  mbuf_write_mem(mb, t->selfkey, KEY_LENGTH);

  uint32_t children_len = 0;

  for (int i = 0; i < ZONE_COUNT; ++i)
  {
    zone = &t->zone[i];
    if (z && zone != z)
      continue;

    children_len = 0;
    LIST_FOREACH(&t->zone[i].children, le) {children_len++;}
      if (!children_len)
        continue;

    mbuf_set_pos(mb, top_pos + 2 + KEY_LENGTH);

    mbuf_write_u8(mb, i); /* zone id */
    mbuf_write_u8(mb, zone->binlen);
    mbuf_write_mem(mb, zone->binrep, zone->binlen);

      uint64_t j = 0;

      LIST_FOREACH(&t->zone[i].children, le) {
          tn = le->data;
          mb_clone = mbuf_clone(mb);

          memcpy(tn->binrep, zone->binrep, ROUTE_LENGTH);
          tn->binlen = stack_layer_add(tn->binrep, j);

      mbuf_write_u8(mb_clone, tn->binlen);
      mbuf_write_mem(mb_clone, (uint8_t *)&tn->binrep, tn->binlen);

      mbuf_set_pos(mb_clone, top_pos);
      if (t->cb) {
        t->cb(t, tn->peer, mb_clone, t->cb_arg);
      }
      mb_clone = mem_deref(mb_clone);
      j++;
      }
  }
    mb = mem_deref(mb);

  /* X:TODO if our address has not changed, do not flush */
  list_flush(&t->dht_items); /* everything has changed, flush dht */

  return;
}

void treeoflife_msg_recv( struct treeoflife *t
            , struct treeoflife_peer *peer
            , struct mbuf *mb
            , uint16_t weight )
{
  size_t pos;
  struct le *le;
  struct mbuf *mb_clone;
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

#if 0 /* PEERS */
    LIST_FOREACH(&t->peers, le) {
      _p = le->data;
      if (!_p->tn) continue;
      if (0 == memcmp(_p->tn->key, sentkey, KEY_LENGTH)) {
        return; /* could be an attack? */
      }
    }
#endif

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
    uint8_t tmp_zonecount;
    int rootcmp;

    tmp_zonecount = mbuf_read_u8(mb);

    if (mbuf_get_left(mb) < (tmp_zonecount * (KEY_LENGTH+KEY_LENGTH+2))) {
      debug("TYPE_BASE+0 length\n");
      goto err;
    }

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
        t->children_ts = tmr_jiffies();
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
    if ( tmp_pzbinlen > ROUTE_LENGTH ) {
      goto err;
    }

    if (tmp_pzbinlen) {
      mbuf_read_mem(mb, tmp_pzbinrep, tmp_pzbinlen);
      debug("ZONE[%u]BINREP[%H]\n", tmp_zoneid, stack_debug, tmp_pzbinrep);
    }

    uint8_t tmp_zbinlen = mbuf_read_u8(mb);
    uint8_t tmp_zbinrep[ROUTE_LENGTH];
    if ( tmp_zbinlen > ROUTE_LENGTH || !tmp_zbinlen) {
      goto err;
    }
    mbuf_read_mem(mb, tmp_zbinrep, tmp_zbinlen);
      debug("MY BINREP[%H]\n", stack_debug, tmp_zbinrep);

      /* copy parent */
      zone->parent->binlen = tmp_pzbinlen;
    memcpy(zone->parent->binrep, tmp_pzbinrep, tmp_pzbinlen );

    /* copy us */
      zone->binlen = tmp_zbinlen;
    memcpy(zone->binrep, tmp_zbinrep, tmp_zbinlen );

    treeoflife_dht_search_or_notify(t, zone, t->selfkey, false);

    treeoflife_children_notify(t, zone);

    return;
  } else if (type == (TYPE_BASE+2) || type == (TYPE_BASE+3) || type == (TYPE_BASE+4)) {
    /* DHT STORE 2 / RETRIEVE 3 / ANSWER 4 */
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
      debug("DST:BINREP[%u][%H]\n", dst_binlen, stack_debug, dst_binrep);

      int _diff = memcmp(dst_binrep
       , t->zone[0].binrep
       , max(dst_binlen, t->zone[0].binlen));

      dhti = treeoflife_dht_find(t, dhtkey);

      if (type == (TYPE_BASE+4)) {
      uint8_t ans_binlen = mbuf_read_u8(mb);
      uint8_t ans_binrep[ROUTE_LENGTH];
      mbuf_read_mem(mb, ans_binrep, ROUTE_LENGTH);

        debug("ANSWER:BINREP[%u][%H]\n", ans_binlen, stack_debug, ans_binrep);

      if (dhti) {
            /* we have it, so update*/
            dhti->binlen = ans_binlen;
            memcpy(dhti->binrep, ans_binrep, ROUTE_LENGTH);
            memcpy(dhti->key, dhtkey, KEY_LENGTH);
            dhti->searching = false;
            /* only lives for 5 minutes */
            tmr_start(&dhti->tmr, 1000 * 60 * 5, treeoflife_dht_item_tmr, dhti);
      }

      goto dht_redirect_or_stay;
        return; /* UNREACHABLE */
      }

    if (type == (TYPE_BASE+3)) {
      debug("TYPE_BASE+3 %p\n", dhti);
      uint8_t search_binlen = 0;
      uint8_t search_binrep[ROUTE_LENGTH];
      (void)treeoflife_search( t
                  , dhtkey
                  , &search_binlen
                  , search_binrep
                  , true);

      if (dhti || search_binlen) {
        /* cool, we have what you are looking for! */
        mb_clone = tol_mbuf_alloc();

        mbuf_advance(mb_clone, -( 2
                                + KEY_LENGTH
                                + 1 /* BINLEN */
                                + ROUTE_LENGTH
                                + 1 /* BINLEN */
                                + ROUTE_LENGTH
                                + KEY_LENGTH /* DHT KEY */
                                + 1 /* BINLEN */
                                + ROUTE_LENGTH));
        pos = mb_clone->pos;

        mbuf_write_u16(mb_clone, arch_htobe16((TYPE_BASE+4))); /* DHT ANSWER */
        mbuf_write_mem(mb_clone, t->selfkey, KEY_LENGTH);

        /* DST */
        mbuf_write_u8(mb_clone, src_binlen);
        mbuf_write_mem(mb_clone, src_binrep, ROUTE_LENGTH);

        /* SRC */
        mbuf_write_u8(mb_clone, t->zone[0].binlen);
        mbuf_write_mem(mb_clone, t->zone[0].binrep, ROUTE_LENGTH);

        if (search_binlen) { /* peermap is > than dht */
          mbuf_write_mem(mb_clone, dhtkey, KEY_LENGTH);
          mbuf_write_u8(mb_clone, search_binlen);
          mbuf_write_mem(mb_clone, search_binrep, ROUTE_LENGTH);
        } else {
          mbuf_write_mem(mb_clone, dhti->key, KEY_LENGTH);
          mbuf_write_u8(mb_clone, dhti->binlen);
          mbuf_write_mem(mb_clone, dhti->binrep, ROUTE_LENGTH);
        }
        /* X:TODO, we should have this signed! */

        dst_peer = treeoflife_route_to_peer(t, src_binlen, src_binrep);
        if (dst_peer && t->cb) {
          /* bombs away! */
          mbuf_set_pos(mb_clone, pos);
          t->cb(t, dst_peer, mb_clone, t->cb_arg);
        }
        mb_clone = mem_deref(mb_clone);
      }
      goto dht_redirect_or_stay;
    } else if (type == (TYPE_BASE+2)){ /* STORAGE */
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
      goto dht_redirect_or_stay;
    }

dht_redirect_or_stay:

      if (t->zone[0].binlen == dst_binlen
        && 0 == _diff) {
        return; /* cool, we end here !*/
      }

    debug("STILL NEED TO REDIRECT DHT\n");
    dst_peer = treeoflife_route_to_peer(t, dst_binlen, dst_binrep);

    if (!dst_peer) {
      debug("DHT;; GUESS IT STOPS WITH US!\n");
      return;
    }

    /* bombs away! */
    mbuf_set_pos(mb, pos_top);

      if (t->cb)
        t->cb(t, dst_peer, mb, t->cb_arg);

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


      /*debug("GOT DIFF OF %d\n", _diff);*/

    treeoflife_dht_add_or_update( t
                  , sentkey
                  , src_binlen
                  , src_binrep
                  , false);


      if (t->zone[0].binlen == dst_binlen
        && 0 == memcmp(dst_binrep
       , t->zone[0].binrep
       , max(dst_binlen, t->zone[0].binlen))) {
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
        t->cb(t, dst_peer, mb, t->cb_arg);

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

        t->tun_cb(t, mb, t->tun_cb_arg);
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
                           , treeoflife_treemsg_h *cb
                           , void *arg)
{
  if (!t) return;
  t->cb = cb;
  t->cb_arg = cb ? arg : NULL;
}

void treeoflife_register_tuncb( struct treeoflife *t
                              , treeoflife_tunnel_h *cb
                              , void *arg )
{
  if (!t) return;
  t->tun_cb = cb;
  t->tun_cb_arg = cb ? arg : NULL;
}

static void _tmr_maintain_cb(void *data)
{
  struct treeoflife *t = data;
  uint64_t now = tmr_jiffies();
/*  debug("now - t->children_ts == %u", now - t->children_ts);
*/  /*debug("\n\n====================\n%H\n====================\n\n", treeoflife_debug, t);*/

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
  size_t pos;
  struct treeoflife *t = data;
  struct mbuf *mb = tol_mbuf_alloc();
  const struct treeoflife_zone *zone;

  mbuf_advance(mb, -( 2
              + KEY_LENGTH /* US */
              + 1 /* zone count */
              + (ZONE_COUNT * KEY_LENGTH) /* ROOT ID */
              + (ZONE_COUNT * 2) /* zone height */
              + (ZONE_COUNT * KEY_LENGTH) /* parent key */
              ));
  pos = mb->pos;

#if 1
  mbuf_write_u16(mb, arch_htobe16((TYPE_BASE+0))); /* type 1 = tree */
  mbuf_write_mem(mb, t->selfkey, KEY_LENGTH);
  mbuf_write_u8(mb, ZONE_COUNT); /* zones count */

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

  mbuf_set_pos(mb, pos);

  if (t->cb)
    t->cb(t, NULL, mb, t->cb_arg);

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

  if (!t)
    return 0;

  err |= re_hprintf(pf, "\nI AM: [%W]\n\n", t->selfkey, KEY_LENGTH);

  for (int i = 0; i < ZONE_COUNT; ++i)
  {
    zone = &t->zone[i];
    err |= re_hprintf(pf, "ZONE[%i][ROOT:%W][HEIGHT:%u]\n", i, &zone->root, KEY_LENGTH, zone->height);
    if (zone->parent) {
      err |= re_hprintf(pf, "  PARENT[%W]\n", zone->parent->key, KEY_LENGTH/*, &zone->parent->peer->sa*/); /*@%J*/
          err |= re_hprintf(pf, "        [%u@%H]\n", zone->parent->binlen, stack_debug, zone->parent->binrep);
    }
      LIST_FOREACH(&zone->children, le) {
          tn = le->data;
          err |= re_hprintf(pf, "  CHILD[%W]\n", tn->key, KEY_LENGTH/*, &tn->peer->sa*/); /*@%J*/
          err |= re_hprintf(pf, "  ROUTE[%u@%H]\n", tn->binlen, stack_debug, tn->binrep);
      }
      //if (!zone->binlen) {
    //  err |= re_hprintf(pf, "  COORDS[ROOT]\n");
      //} else {
        err |= re_hprintf(pf, "  COORDS[%u][%H]\n", zone->binlen, stack_debug, zone->binrep);
      //}
  }

  return err;
}

int treeoflife_dht_debug(struct re_printf *pf, const struct treeoflife *t)
{
  int err = 0;
  struct le *le;
  struct treeoflife_dht_item *dhti = NULL;

    LIST_FOREACH(&t->dht_items, le) {
        dhti = le->data;
        err |= re_hprintf(pf, "[%W][%u@%H]%s\n", dhti->key
                             , KEY_LENGTH
                             , dhti->binlen
                             , stack_debug, dhti->binrep
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
  /*list_flush(&t->peers);*/
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
    memset(t->zone[i].binrep, 0, ROUTE_LENGTH);
    /*slide_compress(0, t->zone[i].binrep, &t->zone[i].binlen);*/
  }

  memcpy(t->selfkey, public_key, KEY_LENGTH);

#if 0
  uint8_t test_slide[ROUTE_LENGTH];
  uint8_t write_slide[ROUTE_LENGTH];

  memset(test_slide, 0, ROUTE_LENGTH);
  memset(write_slide, 0, ROUTE_LENGTH);

  //*(uint16_t*)(void *)write_slide = arch_htole16(4);
  for (int i = 0; i < 10; ++i)
  {
    uint32_t bi = i;
    uint32_t bl = 0;
        if (i == 0) {
          bl = 1;
          *(uint16_t*)(void *)write_slide = 0;
        } else {
      while (bi) {bl++;bi>>=1;}
      *(uint16_t*)(void *)write_slide = arch_htole16(i);
        }

    uint8_t new_BINLEN = 0;

    slide_splice( test_slide
              , 1
              , test_slide
                , bl
                , write_slide
                , &new_BINLEN );

  }


  BREAKPOINT;
#endif

  tmr_init(&t->tmr);
  tmr_start(&t->tmr, 0, _tmr_cb, t);

  tmr_init(&t->tmr_maintain);
  tmr_start(&t->tmr_maintain, 0, _tmr_maintain_cb, t);

  *treeoflifep = t;

  if (err)
    t = mem_deref(t);
  return err;
}

void treeoflife_peer_cleanup(struct treeoflife *t, struct treeoflife_peer *p)
{
  if (!t || !p || (p->tn && p->tn->tree != t))
    return;
  p->tn = mem_deref(p->tn);
}

#if 0
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
#endif

