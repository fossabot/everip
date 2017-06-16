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

static int encode_entry(struct re_printf *pf, const struct odict_entry *e)
{
	struct odict *array;
	struct le *le;
	int err;

	if (!e)
		return 0;

	switch (e->type) {

	case ODICT_OBJECT:
		err = bencode_encode_odict(pf, e->u.odict);
		break;

	case ODICT_ARRAY:
		array = e->u.odict;
		if (!array)
			return 0;

		err = re_hprintf(pf, "l");

		for (le=array->lst.head; le; le=le->next) {

			const struct odict_entry *ae = le->data;

			err |= re_hprintf(pf, "%H", encode_entry, ae);
		}

		err |= re_hprintf(pf, "e");
		break;

	case ODICT_INT:
		err = re_hprintf(pf, "i%" PRId64 "e", e->u.integer);
		break;

	case ODICT_STRING:
		err = re_hprintf(pf, "%u:%r", e->u.pl.l, &e->u.pl);
		break;

	case ODICT_BOOL:
		err = re_hprintf(pf, "%s", e->u.boolean ? "1" : "0");
		break;

#if 0
	case ODICT_NULL:
		err = re_hprintf(pf, "0"); /* is this okay?*/
		break;
#endif

	default:
		re_fprintf(stderr, "bencode: unsupported type %d\n", e->type);
		err = EINVAL;
	}

	return err;
}


int bencode_encode_odict(struct re_printf *pf, const struct odict *o)
{
	struct le *le;
	int err;

	if (!o)
		return 0;

	err = re_hprintf(pf, "d");

	for (le=o->lst.head; le; le=le->next) {

		const struct odict_entry *e = le->data;

		err |= re_hprintf(pf, "%u:%s%H"
						    , str_len(e->key)
						    , e->key
						    , encode_entry, e);
	}

	err |= re_hprintf(pf, "e");

	return err;
}
