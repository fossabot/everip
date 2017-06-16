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


static struct csock *_from_terminaldogma( struct csock *csock
							       		, struct mbuf *mb )
{

	if (!csock || !mb)
		return NULL;

	struct tunif *tun = container_of(csock, struct tunif, tmldogma_cs);

	(void)tun;

	info("VIRTUAL TUNNEL RECV [%u] BYTES\n", mbuf_get_left(mb));

	return NULL;
}


static void tunif_destructor(void *data)
{
	struct tunif *tun = data;
	if (tun->fd > 0) {
		fd_close(tun->fd);
		(void)close(tun->fd);
	}
}

int tunif_init( struct tunif **tunifp )
{
	int err = 0;

	struct tunif *tunif;

	if (!tunifp)
		return EINVAL;

	tunif = mem_zalloc(sizeof(*tunif), tunif_destructor);
	if (!tunif) {
		return ENOMEM;
	}

	tunif->tmldogma_cs.send = _from_terminaldogma;

    *tunifp = tunif;

    return err;
}
