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

static int container_add(const char *name, unsigned idx,
			 enum odict_type type, struct bencode_handlers *h)
{
	struct odict *o = h->arg, *oc;
	char index[64];
	int err;

	if (!name) {
		if (re_snprintf(index, sizeof(index), "%u", idx) < 0)
			return ENOMEM;

		name = index;
	}

	err = odict_alloc(&oc, hash_bsize(o->ht));
	if (err)
		return err;

	err = odict_entry_add(o, name, type, oc);
	mem_deref(oc);
	h->arg = oc;

	return err;
}


static int object_handler(const char *name, unsigned idx,
			  struct bencode_handlers *h)
{
	return container_add(name, idx, ODICT_OBJECT, h);
}


static int array_handler(const char *name, unsigned idx,
			 struct bencode_handlers *h)
{
	return container_add(name, idx, ODICT_ARRAY, h);
}


static int entry_add(struct odict *o, const char *name,
		     const struct bencode_value *val)
{
	switch (val->type) {

	case BENCODE_STRING:
		return odict_entry_add(o, name, ODICT_STRING, &val->v.pl);

	case BENCODE_INT:
		return odict_entry_add(o, name, ODICT_INT, val->v.integer);

	default:
		return ENOSYS;
	}
}


static int object_entry_handler(const char *name, const struct bencode_value *val,
				void *arg)
{
	struct odict *o = arg;

	return entry_add(o, name, val);
}


static int array_entry_handler(unsigned idx, const struct bencode_value *val,
			       void *arg)
{
	struct odict *o = arg;
	char index[64];

	if (re_snprintf(index, sizeof(index), "%u", idx) < 0)
		return ENOMEM;

	return entry_add(o, index, val);
}


int bencode_decode_odict(struct odict **op, uint32_t hash_size, const char *str,
		      size_t len, unsigned maxdepth)
{
	struct odict *o;
	int err;

	if (!op || !str)
		return EINVAL;

	err = odict_alloc(&o, hash_size);
	if (err)
		return err;

	err = bencode_decode(str, len, maxdepth, object_handler, array_handler,
			  object_entry_handler, array_entry_handler, o);
	if (err)
		mem_deref(o);
	else
		*op = o;

	return err;
}
