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

struct treeoflife_node;

struct treeoflife {
	struct list children;
	struct treeoflife_node *self;
	struct tmr tmr;
	struct tmr tmr_maintain;

	treeoflife_treemsg_h *cb;

	uint16_t coordlen;
	int16_t *coords;

	bool children_updated;

};

struct treeoflife_node {
	struct le le;
	uint32_t id;
	uint32_t rootid;
	uint32_t height;
	uint32_t parentid;
};

static void treeoflife_node_destructor(void *data)
{
	struct treeoflife_node *tn = data;
	list_unlink(&tn->le);
}

struct list *treeoflife_children_get( struct treeoflife *t )
{
	return &t->children;
}

uint32_t treeoflife_get_id( struct treeoflife *t )
{
	return (t->self ? t->self->id : 0);
}

static void treeoflife_children_notify( struct treeoflife *t )
{
	struct le *le;
	struct treeoflife_node *tn = NULL;

	debug("treeoflife_children_notify\n");

	struct odict *outdict;
    odict_alloc(&outdict, 8);
	struct pl pl_kind = {
		 .p = "coord"
		,.l = 5
	};
    odict_entry_add(outdict, "_", ODICT_STRING, &pl_kind);
	struct pl pl_coords = {
		 .p = (const uint8_t *)t->coords
		,.l = t->coordlen * 2 /* uint16_t */
	};
    odict_entry_add(outdict, "c", ODICT_STRING, &pl_coords);
    odict_entry_add(outdict, "cl", ODICT_INT, t->coordlen);

    uint32_t i = 0;
    uint32_t bi = 0;
    uint32_t bn = 0;
    bitv_t bibit;
    LIST_FOREACH(&t->children, le) {
        tn = le->data;
        error("[%p] SENDING DICT: %H\n", t, odict_debug, outdict);
        bi = i;
        bitv_init(&bibit, 0xFFFFFFFF, false);
        bn = 0;
        while (bi) {
        	bitv_assign(&bibit, bi, (bi & 1 ? true : false));
        	bn++;
        	bi>>=1;
        }
        if (bn == 0) {
        	bn = 1;
        	/* we still need to represent that there was one node */
        }
		{
			odict_entry_del(outdict, "bi");
			struct pl pl_binrep = {
				 .p = (const uint8_t *)&bibit
				,.l = 4
			};
		    odict_entry_add(outdict, "bi", ODICT_STRING, &pl_binrep);
		    odict_entry_del(outdict, "bl");
		    odict_entry_add(outdict, "bl", ODICT_INT, bn);
		}
		if (t->cb)
			t->cb(t, tn->id, outdict);
		i++;
    }

    outdict = mem_deref(outdict);
	return;
}

void treeoflife_msg_recv( struct treeoflife *t
						, struct odict *o)
{
	if (!t) return;
	uint16_t w = 1;
	error("[%p] GOT DICT: [%p]%H\n", t, o, odict_debug, o);

	const struct odict_entry *o_kind = odict_lookup(o, "_");
	if (!o_kind || o_kind->type != ODICT_STRING)
		return;

	if (o_kind->u.pl.p[0] == 'c' && o_kind->u.pl.p[1] == 'o') {
		debug("coord data?\n");
		/*{ c:(2)[0000] cl:1 bi:(4)[02000000] bl:1 }*/
		const struct odict_entry *o_c = odict_lookup(o, "c");
		const struct odict_entry *o_cl = odict_lookup(o, "cl");
		const struct odict_entry *o_bi = odict_lookup(o, "bi");
		const struct odict_entry *o_bl = odict_lookup(o, "bl");
		if (   !o_c || o_c->type != ODICT_STRING
		    || !o_cl || o_cl->type != ODICT_INT
		    || !o_bi || o_bi->type != ODICT_STRING
		    || !o_bl || o_bl->type != ODICT_INT) {
			/* bad message? */
			return;
		}

		/* remove and update our coords */
		t->coords = mem_deref(t->coords);
		uint16_t mcl = (uint16_t)o_cl->u.integer;
		uint16_t mbl = (uint16_t)o_bl->u.integer;
		t->coordlen = mcl + mbl;
		t->coords = mem_zalloc(sizeof(uint16_t)*t->coordlen, NULL);


		int16_t *msg_coords = (int16_t *)o_c->u.pl.p;
		for (int i = 0; i < mcl; ++i)
		{
			debug("msg_coords[%d] = %d\n", i, msg_coords[i]);
			if (msg_coords[i] < 0) {
				t->coords[i] = msg_coords[i] - w;
			} else {
				t->coords[i] = msg_coords[i] + w;
			}
		}
		bitv_t *bv = (int16_t *)o_bi->u.pl.p;
		for (int i = 0; i < mbl; ++i)
		{
			debug("bitv_val(bv, %d) = %d\n", i, bitv_val(bv, i));
			if (!bitv_val(bv, i)) {
				t->coords[mcl+i] = -1 * w;
			} else {
				t->coords[mcl+i] = w;
			}
		}
	} else if (o_kind->u.pl.p[0] == 't' && o_kind->u.pl.p[1] == 'r') {
		const struct odict_entry *o_id = odict_lookup(o, "id");
		const struct odict_entry *o_rid = odict_lookup(o, "rid");
		const struct odict_entry *o_hei = odict_lookup(o, "h");
		const struct odict_entry *o_pid = odict_lookup(o, "pid");

		if (   !o_id || o_id->type != ODICT_INT
		    || !o_rid || o_rid->type != ODICT_INT
		    || !o_hei || o_hei->type != ODICT_INT
		    || !o_pid || o_pid->type != ODICT_INT) {
			/* bad message? */
			return;
		}

		if (   (uint32_t)o_rid->u.integer > t->self->rootid
			|| ((uint32_t)o_rid->u.integer == t->self->rootid
				&& (uint32_t)o_hei->u.integer + w < t->self->height) )
		{
			t->self->parentid = (uint32_t)o_id->u.integer;
			t->self->height = (uint32_t)o_hei->u.integer + w;
			t->self->rootid = (uint32_t)o_rid->u.integer;
		}

	    struct le *le;
	    struct treeoflife_node *tn = NULL;
	    LIST_FOREACH(&t->children, le) {
	        tn = le->data;
	        if ((uint32_t)o_id->u.integer == tn->id) {
	        	break;
	        } else {
	        	tn = NULL;
	        }
	    }

		if (!tn && (uint32_t)o_pid->u.integer == t->self->id) {
			/* we are the parent of this node */
			tn = mem_zalloc(sizeof(*tn), treeoflife_node_destructor);
			if (!tn) {
				return;
			}
			tn->id = (uint32_t)o_id->u.integer;
			list_append(&t->children, &tn->le, tn);
			debug("CHILDREN NEED UPDATES!\n");
			t->children_updated = true;
		}

		if (tn && (uint32_t)o_pid->u.integer != t->self->id) {
			tn = mem_deref(tn); /* remove from children if need be*/
			debug("CHILDREN NEED UPDATES!\n");
			t->children_updated = true;
		}
	}

}

void treeoflife_register_cb( struct treeoflife *t
						   , treeoflife_treemsg_h *cb)
{
	if (!t) return;
	t->cb = cb;
}

static void _tmr_maintain_cb(void *data)
{
	struct treeoflife *t = data;
	debug("_tmr_maintain_cb\n");
    if (!t->children_updated) {
    	goto out;
    }
    t->children_updated = false;
    debug("going to update children!\n");
    treeoflife_children_notify(t);
out:
	tmr_start(&t->tmr_maintain, 3000 + ((uint8_t)rand_char()), _tmr_maintain_cb, t);
}

static void _tmr_cb(void *data)
{
	struct treeoflife *t = data;
	struct odict *outdict;
    odict_alloc(&outdict, 8);
	struct pl pl_kind = {
		 .p = "tree"
		,.l = 5
	};
    odict_entry_add(outdict, "_", ODICT_STRING, &pl_kind);
    odict_entry_add(outdict, "id", ODICT_INT, t->self->id);
    odict_entry_add(outdict, "rid", ODICT_INT, t->self->rootid);
    odict_entry_add(outdict, "pid", ODICT_INT, t->self->parentid);
    odict_entry_add(outdict, "h", ODICT_INT, t->self->height);

    error("[%p] SENDING DICT: %H\n", t, odict_debug, outdict);

	if (t->cb)
		t->cb(t, 0xFFFFFFFF, outdict);

	outdict = mem_deref(outdict);
	tmr_start(&t->tmr, 2000 + ((uint8_t)rand_char()), _tmr_cb, t);
}

int treeoflife_debug(struct re_printf *pf, const struct treeoflife *t)
{
	int err = 0;
	err |= re_hprintf(pf, "[%p] id:%u, rid:%u, h:%u, pid:%u\n", t
															  , t->self->id
															  , t->self->rootid
															  , t->self->height
															  , t->self->parentid);

    struct le *le;
    struct treeoflife_node *tn = NULL;
    LIST_FOREACH(&t->children, le) {
        tn = le->data;
        err |= re_hprintf(pf, "  [%p] CHILD: %u\n", t, tn->id);
    }

    for (int i = 0; i < t->coordlen; ++i)
    {
    	err |= re_hprintf(pf, "  [%p] COORD[%u]: %d\n", t, i, t->coords[i]);
    }

	return err;
}

static void treeoflife_destructor(void *data)
{
	struct treeoflife *t = data;
	list_flush(&t->children);
	tmr_cancel(&t->tmr);
	tmr_cancel(&t->tmr_maintain);
	t->self = mem_deref(t->self);
	t->coords = mem_deref(t->coords);
}

int treeoflife_init( struct treeoflife **treeoflifep )
{
	int err = 0;
	struct treeoflife *t;

	if (!treeoflifep)
		return EINVAL;

	t = mem_zalloc(sizeof(*t), treeoflife_destructor);
	if (!t)
		return ENOMEM;

	list_init(&t->children);

	/* create self */
	t->self = mem_zalloc(sizeof(*t->self), treeoflife_node_destructor);
	if (!t->self) {
		err = ENOMEM;
		goto out;
	}

	t->self->id = rand_u32();
	t->self->rootid = t->self->id;
	t->self->height = 0;
	t->self->parentid = 0;

	t->coordlen = 1;
	t->coords = mem_zalloc(sizeof(uint16_t)*t->coordlen, NULL);


	tmr_init(&t->tmr);
	tmr_start(&t->tmr, 0, _tmr_cb, t);

	tmr_init(&t->tmr_maintain);
	tmr_start(&t->tmr_maintain, 0, _tmr_maintain_cb, t);

	*treeoflifep = t;

out:
	if (err)
		t = mem_deref(t);
	return err;
}

/* */

