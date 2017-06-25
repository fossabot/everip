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

#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <net/if.h>

static struct csock *_from_terminaldogma( struct csock *csock
							       		, struct mbuf *mb )
{
	int err = 0;
	ssize_t n;

	if (!csock || !mb)
		return NULL;

	struct tunif *tun = container_of(csock, struct tunif, tmldogma_cs);

	if (mbuf_get_left(mb) < 4) {
		return NULL;
	}

    ((uint16_t*)(void *)mbuf_buf(mb))[0] = 0;
    ((uint16_t*)(void *)mbuf_buf(mb))[1] = arch_htobe16(0x86DD);

    error("going back out...%u[%w]\n", mbuf_get_left(mb), mbuf_buf(mb), 8);

    n = write(tun->fd, mbuf_buf(mb), mbuf_get_left(mb));
	error("WROTE %d\n", n);

	if (n < 0) {
		err = errno;

		if (EAGAIN == err)
			goto out;

#ifdef EWOULDBLOCK
		if (EWOULDBLOCK == err)
			goto out;
#endif
		goto out;
	}

out:
	return NULL;
}

static void tun_read_handler(int flags, void *arg)
{
	struct tunif *tun = arg;
	(void)flags;

	struct mbuf *mb = mbuf_alloc(EVER_OUTWARD_MBE_LENGTH*2);

	int err = 0;
	ssize_t n;

	if (!mb)
		return;

	n = read( tun->fd
			, mb->buf + EVER_OUTWARD_MBE_POS
			, mb->size - EVER_OUTWARD_MBE_POS
			);
	if (n < 0) {
		err = errno;

		if (EAGAIN == err)
			goto out;

#ifdef EWOULDBLOCK
		if (EWOULDBLOCK == err)
			goto out;
#endif
		goto out;
	}

	mb->pos = EVER_OUTWARD_MBE_POS;
	mb->end = n + EVER_OUTWARD_MBE_POS;

	(void)mbuf_resize(mb, mb->end);

	if (mbuf_get_left(mb) < 4) {
		goto out;
	}

    csock_forward(&tun->tmldogma_cs, mb);

 out:
	mem_deref(mb);

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

    tunif->fd = open("/dev/net/tun", O_RDWR);
    if (tunif->fd < 0) {
        tunif = mem_deref(tunif);
        return EINVAL;
    }

    struct ifreq ifr = { .ifr_flags = IFF_TUN};
    if (ioctl(tunif->fd, TUNSETIFF, &ifr) < 0) {
        err = errno;
        goto err;
    }

    strncpy(tunif->name, ifr.ifr_name, TUN_IFNAMSIZ);

    /* setup event handler */
	err = fd_listen( tunif->fd
		           , FD_READ
		           , tun_read_handler
		           , tunif);
	if (err) {
        goto err;
	}

	tunif->tmldogma_cs.send = _from_terminaldogma;

    *tunifp = tunif;
err:
    return err;
}
