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

#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <fcntl.h>

struct netevent {
	int fd;
};

static void _read_handler(int flags, void *arg)
{
	struct netevent *ne = arg;
	int err = 0;
	ssize_t n;
	uint8_t msg[2048];

	n = read(ne->fd, msg, 2048);
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

	struct rt_msghdr *hdr = (struct rt_msghdr *)(void *)msg;

	if (hdr->rtm_type != RTM_IFINFO) {
		return;
	}

	struct if_msghdr *ifm = (struct if_msghdr *)hdr;

	char _ifname[IF_NAMESIZE];
	if_indextoname(ifm->ifm_index, _ifname);

	info( "IF[%s] has changed %s\n"
		 , _ifname
		 , hdr->rtm_flags & RTF_UP ? "UP" : "DOWN");

 out:
 	return;
}

static void netevent_destructor(void *data)
{
	struct netevent *netevent = data;
	if (netevent->fd > 0) {
		fd_close(netevent->fd);
		(void)close(netevent->fd);
	}
}

int netevent_init( struct netevent **neteventp )
{
	int err = 0;

	struct netevent *netevent;

	if (!neteventp)
		return EINVAL;

	netevent = mem_zalloc(sizeof(*netevent), netevent_destructor);
	if (!netevent) {
	    netevent = mem_deref(netevent);
		return ENOMEM;
	}

    netevent->fd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (netevent->fd < 0) {
        netevent = mem_deref(netevent);
        return EINVAL;
    }

	net_sockopt_blocking_set(netevent->fd, false);

	err = fcntl(netevent->fd, F_SETFD, FD_CLOEXEC);
	if (err) {
		goto err;
	}

    /*re_printf("Initialized netevent\n");*/

    /* setup event handler */
	err = fd_listen( netevent->fd
		           , FD_READ
		           , _read_handler
		           , netevent);
	if (err) {
        goto err;
	}

    *neteventp = netevent;

    return err;

err:
	netevent = mem_deref(netevent);
	return err;

}
