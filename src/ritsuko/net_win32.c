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

struct netevent {
	void *gendo;
};

static void netevent_destructor(void *data)
{
	struct netevent *netevent = data;
	(void)netevent;
}

int netevent_init( struct netevent **neteventp )
{
	int err = 0;

	struct netevent *netevent;

	if (!neteventp)
		return EINVAL;

	netevent = mem_zalloc(sizeof(*netevent), netevent_destructor);
	if (!netevent) {
		return ENOMEM;
	}

	info("netevents is currently not supported on win32\n");

	*neteventp = netevent;

	return err;
}
