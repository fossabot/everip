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

static void geofront_destructor(void *data)
{
	struct geofront *g = data;
	(void)g;
}

int geofront_init( struct geofront **geofrontp )
{
	struct geofront *g;

	if (!geofrontp)
		return EINVAL;

	g = mem_zalloc(sizeof(*g), geofront_destructor);
	if (!g)
		return ENOMEM;

	*geofrontp = g;

	return 0;
}


