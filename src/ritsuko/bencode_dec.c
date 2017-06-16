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


static bool is_number(int64_t *i, const struct pl *pl)
{
	bool neg = false;
	const char *p;
	const char *pe;
	int64_t e = 0;

	if (!pl->l)
		return false;

	p = pl->p;
	pe = &pl->p[pl->l];

	bool end = false;

	while (p < pe && !end) {
	    switch (*p) {
	    	case '-':
	    		if (neg) {
		    		return false; /* what, we already were negative! */
		    	}
		        neg = true;
		        p++;
		        break;
			case '0': /* STRING @FALLTHROUGH@ */
			case '1': /* STRING @FALLTHROUGH@ */
			case '2': /* STRING @FALLTHROUGH@ */
			case '3': /* STRING @FALLTHROUGH@ */
			case '4': /* STRING @FALLTHROUGH@ */
			case '5': /* STRING @FALLTHROUGH@ */
			case '6': /* STRING @FALLTHROUGH@ */
			case '7': /* STRING @FALLTHROUGH@ */
			case '8': /* STRING @FALLTHROUGH@ */
			case '9': /* STRING */
		        e *= 10;
		        e += *p - '0';
		        p++;
		        break;
		    default:
			    end = true;
		    	break;
	    }
	}

	if (neg) {
		e = -e;
	}

    *i = e;

	return true;
}

static inline int chkval(struct pl *val, const char *p)
{
	if (!val->p || p<val->p)
		return EINVAL;

	val->l = p - val->p;

	return 0;
}

static int _bencode_decode(const char **str, size_t *len,
			unsigned depth, unsigned maxdepth,
			bencode_object_h *oh, bencode_array_h *ah,
			bencode_object_entry_h *oeh, bencode_array_entry_h *aeh,
			void *arg)
{
	bool inobj = false, inarray = false, ininteger = false;
	struct pl name = PL_INIT, val = PL_INIT;
	unsigned idx = 0;
	int err;

	for (; *len>0; ++(*str), --(*len)) {
		switch (**str) {
			case 'd': /* DICT */
				if (inobj || inarray) {

					struct bencode_handlers h = {oh,ah,oeh,aeh,arg};

					if (depth >= maxdepth)
						return EOVERFLOW;

					if (inobj && !name.p)
						return EBADMSG;

					if (h.oh) {
						char *oname = NULL;
						if (name.p) pl_strdup(&oname, &name);
						err = h.oh(oname, idx, &h);
						mem_deref(oname);
					}

					name = pl_null;

					err = _bencode_decode(str, len, depth + 1,
							   maxdepth, h.oh, h.ah,
							   h.oeh, h.aeh, h.arg);
					if (err)
						return err;

					if (inarray)
						++idx;

				} else {
					inobj = true;
				}
				break;


			case 'l': /* LIST */
				if (inobj || inarray) {

					struct bencode_handlers h = {oh,ah,oeh,aeh,arg};

					if (depth >= maxdepth)
						return EOVERFLOW;

					if (inobj && !name.p)
						return EBADMSG;

					if (h.ah) {
						char *oname = NULL;
						if (name.p) pl_strdup(&oname, &name);
						err = h.ah(oname, idx, &h);
						mem_deref(oname);
					}

					name = pl_null;

					err = _bencode_decode(str, len, depth + 1,
							   maxdepth, h.oh, h.ah,
							   h.oeh, h.aeh, h.arg);
					if (err)
						return err;

					if (inarray)
						++idx;

				} else {
					inarray = true;
					idx = 0;
				}
				break;

			case 'i': /* INTEGER */
				ininteger = true;
				val  = pl_null;
				break;

			case ':': /* STRING */
				if ((!inobj && !inarray) || chkval(&val, *str))
					return EBADMSG;

				int64_t slen = 0;
				is_number(&slen, &val);

				/*info("STRLEN? %u\n", slen);*/

				if (slen <= 0 || *len < (size_t)(slen+1))
					return EBADMSG;

				val.p = *str + 1;
				val.l = slen;

				*str += slen; /* skip this many */
				*len -= slen;

				/*info("STR? %r\n", &val);*/

				if (inobj) {
					if (name.p) {
						/* this would then be an obj entry? */
						char *oname;
						struct bencode_value oval;
						oval.type = BENCODE_STRING;
						pl_strdup(&oname, &name);
						oval.v.pl = val;

						/*info("NAME? %r\n", &name);*/
						/*info("VALUE? %r\n", &val);*/
						if (oeh) {
							err = oeh(oname, &oval, arg);
						}
						mem_deref(oname);
						if (err) return err;
						name = pl_null;
					} else { /* no name... */
						/* set as name */
						name = val;
					}
				} else { /* in array! */
					struct bencode_value oval;
					oval.type = BENCODE_STRING;
					oval.v.pl = val;
					if (aeh) {
						err = aeh(idx, &oval, arg);
					}
					++idx;
					if (err) return err;
				}

				val  = pl_null;

				break;

			case 'e': /* END */
				if ((!inobj && !inarray))
					return EBADMSG;

				if (chkval(&val, *str))
					return 0;

				if (!ininteger) {
					BREAKPOINT;
					return EBADMSG;
				}

				int64_t oint = 0;
				if (!is_number(&oint, &val))
					return EBADMSG;

				if (inobj) {
					char *oname;
					struct bencode_value oval;
					oval.type = BENCODE_INT;
					oval.v.integer = oint;
					pl_strdup(&oname, &name);
					/*info("NAME? %r\n", &name);*/
					/*info("VALUE? %d\n", oval.v.integer);*/
					if (oeh) {
						err = oeh(oname, &oval, arg);
					}
					mem_deref(oname);
					if (err) return err;
					name = pl_null;
				} else { /* array ? */
					struct bencode_value oval;
					oval.type = BENCODE_INT;
					oval.v.integer = oint;
					if (aeh) {
						err = aeh(idx, &oval, arg);
					}
					++idx;
					if (err) return err;
				}
				ininteger = false;
				val  = pl_null;
				break;

			default:
				if (val.p)
					break;
				val.p = *str;
				val.l = 0;
				break;

		}
	}

	if (inobj || inarray) {
		return EBADMSG;
	}

	return 0;
}


int bencode_decode(const char *str, size_t len, unsigned maxdepth,
		bencode_object_h *oh, bencode_array_h *ah,
		bencode_object_entry_h *oeh, bencode_array_entry_h *aeh, void *arg)
{
	if (!str)
		return EINVAL;

	return _bencode_decode(&str, &len, 0, maxdepth, oh, ah, oeh, aeh, arg);
}
