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
};

struct treeoflife_node {
	uint64_t root_id;
	uint16_t height;
	struct treeoflife_node *parent;
};

static void treeoflife_destructor(void *data)
{
	struct treeoflife *t = data;
	list_flush(&t->children);
}

int treeoflife_init( struct treeoflife **treeoflifep )
{
	struct treeoflife *t;

	if (!treeoflifep)
		return EINVAL;

	t = mem_zalloc(sizeof(*t), treeoflife_destructor);
	if (!t)
		return ENOMEM;

	list_init(&t->children);

	*treeoflifep = t;

	return 0;
}

