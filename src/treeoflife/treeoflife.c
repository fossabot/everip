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

	treeoflife_treemsg_h *cb;
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

void treeoflife_msg_recv( struct treeoflife *t
						, struct odict *o)
{
	if (!t) return;
	uint16_t w = 1;
	error("[%p] GOT DICT: [%p]%H\n", t, o, odict_debug, o);

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
	}

	if (tn && (uint32_t)o_pid->u.integer != t->self->id) {
		tn = mem_deref(tn); /* remove from children if need be*/
	}

}

void treeoflife_register_cb( struct treeoflife *t
						   , treeoflife_treemsg_h *cb)
{
	if (!t) return;
	t->cb = cb;
}

static void _tmr_cb(void *data)
{
	struct treeoflife *t = data;
	struct odict *outdict;
    odict_alloc(&outdict, 8);
    odict_entry_add(outdict, "id", ODICT_INT, t->self->id);
    odict_entry_add(outdict, "rid", ODICT_INT, t->self->rootid);
    odict_entry_add(outdict, "pid", ODICT_INT, t->self->parentid);
    odict_entry_add(outdict, "h", ODICT_INT, t->self->height);

    error("[%p] SENDING DICT: %H\n", t, odict_debug, outdict);

	if (t->cb)
		t->cb(t, outdict);

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
        err |= re_hprintf(pf, "  [%p] CHILD: %u\n", tn, tn->id);
    }

	return err;
}

static void treeoflife_destructor(void *data)
{
	struct treeoflife *t = data;
	list_flush(&t->children);
	tmr_cancel(&t->tmr);
	t->self = mem_deref(t->self);
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

	tmr_init(&t->tmr);
	tmr_start(&t->tmr, 0, _tmr_cb, t);

	*treeoflifep = t;

out:
	if (err)
		t = mem_deref(t);
	return err;
}

