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


struct modapp {
	struct mod *mod;
	struct le le;
};


static struct list modappl;

#ifdef STATIC

/* Declared in static.c */
extern const struct mod_export *mod_table[];
static const struct mod_export *find_module(const struct pl *pl)
{
	struct pl name;
	uint32_t i;

	if (re_regex(pl->p, pl->l, "[^.]+.[^]*", &name, NULL))
		name = *pl;

	for (i=0; ; i++) {
		const struct mod_export *me = mod_table[i];
		if (!me)
			return NULL;
		if (0 == pl_strcasecmp(&name, me->name))
			return me;
	}

	return NULL;
}
#endif


static int load_module( struct mod **modp
					  , const struct pl *name)
{
	struct mod *m = NULL;
	int err = 0;

	if (!name)
		return EINVAL;

#ifdef STATIC
	/* Try static first */
	err = mod_add(&m, find_module(name));
	if (!err)
		goto out;

 out:

#endif

	if (err) {
		warning("module %r: %m\n", name, err);
	}
	else if (modp)
		*modp = m;

	return err;
}

void module_app_unload(void)
{
	list_flush(&modappl);
}


int module_preload(const char *module)
{
	struct pl name;

	if (!module)
		return EINVAL;

	pl_set_str(&name, module);

	return load_module(NULL, &name);
}
