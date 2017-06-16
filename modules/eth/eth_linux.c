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

struct eth_csock {
	struct csock csock;
	int fd;
	uint8_t mac[6];

	size_t blen;
	uint8_t *bptr;
};

static struct csock *eth_handle_incoming( struct csock *csock
										, struct mbuf *mb )
{
	int err = 0;
	ssize_t n;
	struct eth_csock *eth_c = container_of(csock, struct eth_csock, csock);

	size_t pfix = mb->pos;

	mbuf_set_pos(mb, 0);
	struct csock_addr *csaddr = (struct csock_addr *) mbuf_buf(mb);

	mbuf_set_pos(mb, pfix);

	mbuf_advance(mb, -WIRE_ETHFRAME_LENGTH);
	pfix = mb->pos;
	/* write dst */
	if (csaddr->flags & CSOCK_ADDR_BCAST) {
		error("ETH BROADCAST\n");
		mbuf_fill(mb, 0xFF, 6);
	} else {
		mbuf_write_mem(mb, csaddr->a.mac, 6);
	}
	/* write src */
	mbuf_write_mem(mb, eth_c->mac, 6);
	/* write type */
	mbuf_write_u16(mb, arch_htobe16(0xCF01));

	mbuf_set_pos(mb, pfix);

    n = write( eth_c->fd
    		 , mbuf_buf(mb)
    		 , mbuf_get_left(mb));

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

static void _read_handler(int flags, void *arg)
{
	int err = 0;
	ssize_t n;
	struct sockaddr_ll addr;
	uint32_t addrlen;
	struct eth_csock *eth_c = arg;
	(void)flags;

	struct mbuf *mb = mbuf_alloc(EVER_OUTWARD_MBE_LENGTH*2);
	error("eth _read_handler\n");

	if (!mb)
		return;

	n = read( eth_c->fd
			, mb->buf + EVER_OUTWARD_MBE_POS
			, mb->size - EVER_OUTWARD_MBE_POS
			);

	addrlen = sizeof(struct sockaddr_ll);
	n = recvfrom( eth_c->fd
				, mb->buf + EVER_OUTWARD_MBE_POS
				, mb->size - EVER_OUTWARD_MBE_POS
				, 0
				, (struct sockaddr*) &addr
				, &addrlen);

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

	size_t pfix = mb->pos;
	mbuf_set_pos(mb, 0);
	struct csock_addr *csaddr = (struct csock_addr *)mbuf_buf(mb);
	memset(csaddr, 0, sizeof(struct csock_addr));

	memcpy(csaddr->a.mac, addr.sll_addr, 6);

	struct PACKONE {
		uint16_t flags;
		uint32_t hash;
	} tmp;

	tmp.flags = CSOCK_ADDR_MAC;
	tmp.hash = hash_joaat(csaddr->a.mac, 6);

	csaddr->hash = hash_joaat((uint8_t *)&tmp, 6);
	csaddr->len = CSOCK_ADDR_LENMAC;
	csaddr->flags = tmp.flags;

	mbuf_set_pos(mb, pfix);
    csock_forward(&eth_c->csock, mb);

 out:
	mem_deref(mb);

}

static int _find_bpf(void)
{
	int r, i, _bpf;
	for (r = 0; r < 100; ++r) {
	    for (i = 0; i < 256; i++) {
	        char b[11] = { 0 };
	        snprintf(b, 10, "/dev/bpf%i", i);
	        _bpf = open(b, O_RDWR);
	        if (_bpf != -1) {
	        	return _bpf;
	        }
	    }
	    sys_usleep(1000 * 100);
	}
	return -1;
}


static void eth_c_destructor(void *data)
{
	struct eth_csock *eth_c = data;
	csock_stop(&eth_c->csock);

	eth_c->bptr = mem_deref(eth_c->bptr);

	if (eth_c->fd > 0) {
		/* clear socks */
		fd_close(eth_c->fd);
		(void)close(eth_c->fd);
	}

}

static struct eth_csock *eth_c = NULL;

static int module_init(void)
{
	int err = 0;
	struct ifaddrs *ifa, *ifa_p;

	eth_c = mem_zalloc(sizeof(*eth_c), eth_c_destructor);
	if (!eth_c)
		return ENOMEM;

	/* temporary */
	char *ifname = "en0";

	eth_c->fd = _find_bpf();
	if (eth_c->fd < 0) {
		err = EINVAL;
		goto out;
	}

    if (getifaddrs(&ifa)) {
    	err = EINVAL;
        goto out;
    }

    for (ifa_p = ifa; ifa_p; ifa_p = ifa_p->ifa_next) {
        if (ifa_p->ifa_addr->sa_family == AF_LINK
          	&& !strcmp(ifa_p->ifa_name, ifname)) {
            memcpy(eth_c->mac, LLADDR((struct sockaddr_dl *)(void *)ifa_p->ifa_addr), 6);
            break;
        }
    }

    freeifaddrs(ifa);

    {
	    struct ifreq ifr = { .ifr_name = { 0 } };
	    strcpy(ifr.ifr_name, ifname);
	    if (0 != ioctl(eth_c->fd, BIOCSETIF, &ifr)) {
	        warning( "ioctl(BIOCSETIF, [%s]) [%s]"
	        	   , ifname
	        	   , strerror(errno));
	        err = errno;
	        goto out;
	    }
    }
    {
	    int _blen = 1;
	    if (-1 == ioctl(eth_c->fd, BIOCIMMEDIATE, &_blen)) {
	        warning("ioctl(BIOCIMMEDIATE) [%s]", strerror(errno));
	        err = errno;
	        goto out;
	    }
	    if (-1 == ioctl(eth_c->fd, BIOCGBLEN, &_blen)) {
	        warning("ioctl(BIOCGBLEN) [%s]", strerror(errno));
	        err = errno;
	        goto out;
	    }

	    eth_c->blen = _blen;
	    eth_c->bptr = mem_zalloc(_blen, NULL);
    }
    {
	    struct bpf_program prog = {
	        .bf_len = (sizeof(_FILTER) / sizeof(struct bpf_insn)),
	        .bf_insns = _FILTER,
	    };
	    if (ioctl(eth_c->fd, BIOCSETF, &prog) == -1) {
	        warning( "ioctl(BIOCSETF) [%s]"
	        	   , strerror(errno));
	        err = errno;
	        goto out;
	    }
    }

    err = net_sockopt_blocking_set(eth_c->fd, false);
    if (err) {
    	goto out;
    }

	err = fd_listen( eth_c->fd
		           , FD_READ
		           , _read_handler
		           , eth_c);
	if (err) {
        goto out;
	}

	eth_c->csock.send = eth_handle_incoming;

	conduits_register( everip_conduits()
					 , "ETH"
					 , "Ethernet L2 Driver Conduit"
					 , (struct csock *)eth_c
					 );

out:
	if (err) {
		eth_c = mem_deref(eth_c);
	}
	return err;
}


static int module_close(void)
{
	eth_c = mem_deref(eth_c);
	return 0;
}


const struct mod_export DECL_EXPORTS(eth) = {
	"eth",
	"conduit",
	module_init,
	module_close
};
