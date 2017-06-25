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

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#undef LIST_INIT
#undef LIST_FOREACH

#include <re.h>
#include <everip.h>
#include <string.h>

struct eth_module {
	struct list conduits;
};

struct eth_csock {
	struct csock csock;

	struct le le;

	uint8_t ifname[IFNAMSIZ];

	int fd;
	uint8_t mac[6];

	size_t blen;
	uint8_t *bptr;
};

static struct bpf_insn _FILTER[] = {
	 BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12)
	,BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xCF01, 1, 0)
	,BPF_STMT(BPF_RET+BPF_K, 0)
	,BPF_STMT(BPF_RET+BPF_K, ~0u)
};

static struct csock *eth_handle_incoming( struct csock *csock
										, struct mbuf *mb )
{
	int err = 0;
	ssize_t n;
	struct eth_csock *eth_c = container_of(csock, struct eth_csock, csock);

	/*error("[ETH:PPRE] %w\n", mb->buf, mb->size);*/
	size_t pfix = mb->pos;

	mbuf_set_pos(mb, 0);
	struct csock_addr *csaddr = (struct csock_addr *) mbuf_buf(mb);

	mbuf_set_pos(mb, pfix);

	mbuf_advance(mb, -WIRE_ETHFRAME_LENGTH);
	pfix = mb->pos;
	/* write dst */
	if (csaddr->flags & CSOCK_ADDR_BCAST) {
		/*error("ETH BROADCAST\n");*/
		mbuf_fill(mb, 0xFF, 6);
	} else {
		mbuf_write_mem(mb, csaddr->a.mac, 6);
	}
	/* write src */
	mbuf_write_mem(mb, eth_c->mac, 6);
	/* write type */
	mbuf_write_u16(mb, arch_htobe16(0xCF01));

	mbuf_set_pos(mb, pfix);

	/*error("[ETH:SEND] %w\n", mbuf_buf(mb), mbuf_get_left(mb));*/

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

static void _process_frame( struct eth_csock *eth_c
						  , uint8_t dst[6]
						  , uint8_t src[6]
						  , struct mbuf *mb)
{
	if (!mb)
		return;

	size_t pfix = mb->pos;
	mbuf_set_pos(mb, 0);
	struct csock_addr *csaddr = (struct csock_addr *)mbuf_buf(mb);
	memset(csaddr, 0, sizeof(struct csock_addr));

	memcpy(csaddr->a.mac, src, 6);

	struct PACKONE {
		uint16_t flags;
		uint32_t hash;
	} tmp;

	tmp.flags = CSOCK_ADDR_MAC;
	tmp.hash = hash_joaat(csaddr->a.mac, 6);

	csaddr->hash = hash_joaat((uint8_t *)&tmp, 6);
	csaddr->len = CSOCK_ADDR_LENMAC;
	csaddr->flags = tmp.flags;

	debug("HASH IS SET TO %u [%W]\n", csaddr->hash, src, 6);

	mbuf_set_pos(mb, pfix);

}

static void _eth_read_handler(int flags, void *arg)
{
	ssize_t n = 0;
	ssize_t off = 0;
	struct mbuf *mb = NULL;
	struct eth_csock *eth_c = arg;
	(void)flags;

    n = read( eth_c->fd
			, eth_c->bptr
			, eth_c->blen);

    if (n < 1) {
        return;
    }
    if (n < (ssize_t)sizeof(struct bpf_hdr)) {
        debug("ETH: DROP RUNT\n");
        return;
    }
    while (off < n) {
        struct bpf_hdr *bpfp = (struct bpf_hdr *)(void *)&eth_c->bptr[off];
        struct wire_ethframe *ehdr = (struct wire_ethframe *)(void *)&eth_c->bptr[off + bpfp->bh_hdrlen];
        ASSERT_TRUE(off + bpfp->bh_hdrlen + bpfp->bh_datalen <= n);
        ASSERT_TRUE(arch_htobe16(0xCF01) == ehdr->type);
        mb = mbuf_alloc(EVER_OUTWARD_MBE_LENGTH*2);
		memcpy( mb->buf + EVER_OUTWARD_MBE_POS
			  , &eth_c->bptr[off + bpfp->bh_hdrlen + WIRE_ETHFRAME_LENGTH]
			  , bpfp->bh_datalen - WIRE_ETHFRAME_LENGTH
			  );

		mb->pos = EVER_OUTWARD_MBE_POS;
		mb->end = (bpfp->bh_datalen - WIRE_ETHFRAME_LENGTH) + EVER_OUTWARD_MBE_POS;

		(void)mbuf_resize(mb, mb->end);
		_process_frame(eth_c, ehdr->dst, ehdr->src, mb);
	    csock_forward(&eth_c->csock, mb);
		mb = mem_deref(mb);
        off += BPF_WORDALIGN(bpfp->bh_hdrlen + bpfp->bh_caplen); }
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

static int register_eth_conduit( const char ifname[IFNAMSIZ]
							   , void *arg )
{

	int err = 0;
	struct le *le;
	struct eth_csock *eth_c;
	struct ifaddrs *ifa, *ifa_p;

	struct eth_module *eth_m = arg;

	LIST_FOREACH(&eth_m->conduits, le) {
		eth_c = le->data;
		if (eth_c && !strcmp((const char *)eth_c->ifname, ifname)) {
			debug("register_eth_conduit tried to double;\n");
			return 0;
		}
	}

	eth_c = mem_zalloc(sizeof(*eth_c), eth_c_destructor);
	if (!eth_c)
		return ENOMEM;

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
	    int seeSent = 0;
	    if (ioctl(eth_c->fd, BIOCSSEESENT, &seeSent) == -1) {
	        warning( "ioctl(BIOCSSEESENT) [%s]", strerror(errno));
	        err = errno;
	        goto out;
	    }
    }
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
		           , _eth_read_handler
		           , eth_c);
	if (err) {
        goto out;
	}

	strncpy((char *)eth_c->ifname, ifname, IFNAMSIZ);

	eth_c->csock.send = eth_handle_incoming;

	conduits_register( everip_conduits()
					 , (const char *)eth_c->ifname
					 , "Ethernet L2 Driver Conduit"
					 , (struct csock *)eth_c
					 );

	list_append(&eth_m->conduits, &eth_c->le, eth_c);

out:
	if (err) {
		eth_c = mem_deref(eth_c);
	}
	return err;

}

static bool _if_handler( const char *ifname
					   , const struct sa *sa
					   , void *arg)
{
	int err = 0;
	struct eth_module *eth_m = arg;

	struct pl num;
	err = re_regex(ifname, strlen(ifname), "en[0-9]+", &num);
	if (err) {
		/*error("%s is not an ethernet if! [%u]\n", ifname, err);*/
		return false;
	}
	
	register_eth_conduit(ifname, eth_m);
	return false;
}

static void eth_m_destructor(void *data)
{
	struct eth_module *eth_m = data;
	list_flush(&eth_m->conduits);
	return;
}

static struct eth_module *eth_m = NULL;

static int module_init(void)
{
	int err = 0;

	eth_m = mem_zalloc(sizeof(*eth_m), eth_m_destructor);
	if (!eth_m)
		return ENOMEM;

	list_init(&eth_m->conduits);

	net_getifaddrs(_if_handler, eth_m);

	return err;
}


static int module_close(void)
{
	eth_m = mem_deref(eth_m);
	return 0;
}


const struct mod_export DECL_EXPORTS(eth) = {
	"eth",
	"conduit",
	module_init,
	module_close
};
