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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
#include <net/if.h>
#include <string.h>
#include <netdb.h>
#include <net/if_var.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <netinet/in.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>

#define APPLE_UTUN_CONTROL "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME 2

/*
interface usage referenced from
https://opensource.apple.com/source/xnu/xnu-2050.7.9/bsd/net/if_utun.c.auto.html
*/

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

	/* hack; we only support ipv6 */
    ((uint16_t*)(void *)mbuf_buf(mb))[0] = 0;
    ((uint16_t*)(void *)mbuf_buf(mb))[1] = 7680;

    n = write(tun->fd, mbuf_buf(mb), mbuf_get_left(mb));

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

	uint16_t af_be = ((uint16_t*)(void *)mbuf_buf(mb))[1];
	if (af_be != 7680) {
		/* only handle ipv6 */
		goto out;
	}
    ((uint16_t*)(void *)mbuf_buf(mb))[0] = 0;
    ((uint16_t*)(void *)mbuf_buf(mb))[1] = arch_htobe16(0x86DD);

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
	    tunif = mem_deref(tunif);
		return ENOMEM;
	}

    tunif->fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (tunif->fd < 0) {
        tunif = mem_deref(tunif);
        return EINVAL;
    }

    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, APPLE_UTUN_CONTROL, strlen(APPLE_UTUN_CONTROL));

    if (ioctl(tunif->fd, CTLIOCGINFO, &info) < 0) {
        err = errno;
        goto err;
    }

    struct sockaddr_ctl addr;
    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0;

    if (connect(tunif->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        err = errno;
        goto err;
    }

    uint32_t name_len = TUN_IFNAMSIZ;

    if (getsockopt( tunif->fd
    			  , SYSPROTO_CONTROL
    			  , UTUN_OPT_IFNAME
    			  , tunif->name
    			  , (uint32_t*)&name_len)) {
	    err = errno;
	    goto err;
	}

	net_sockopt_blocking_set(tunif->fd, false);

	err = fcntl(tunif->fd, F_SETFD, FD_CLOEXEC);
	if (err) {
		goto err;
	}

    /*re_printf("Initialized utun interface [%s]\n", tunif->name);*/

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

    return err;

err:
	tunif = mem_deref(tunif);
	return err;

}
