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

#define __USE_MISC
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct eth_module {
  struct list conduits;
};

struct eth_csock {
  struct csock csock;

  struct le le;
  uint8_t ifname[IFNAMSIZ];
  struct sockaddr_ll sll;

  int fd;
  uint8_t mac[6];
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

  n = sendto( eth_c->fd
            , mbuf_buf(mb)
            , mbuf_get_left(mb)
            , 0
            , (struct sockaddr*)&eth_c->sll
            , sizeof(struct sockaddr_ll));

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

static void _eth_read_handler(int flags, void *arg)
{
  int err = 0;
  ssize_t n;
  size_t pfix;
  uint32_t addrlen;
  struct mbuf *mb = NULL;
  struct sockaddr_ll addr;
  struct eth_csock *eth_c = arg;

  (void)flags;

  mb = mbuf_alloc(EVER_OUTWARD_MBE_LENGTH*2);

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

  pfix = mb->pos;
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

  debug("HASH IS SET TO %u [%W]\n", csaddr->hash, addr.sll_addr, 6);

  mbuf_set_pos(mb, pfix+WIRE_ETHFRAME_LENGTH);

  csock_forward(&eth_c->csock, mb);

 out:
  mem_deref(mb);

}

static void eth_c_destructor(void *data)
{
  struct eth_csock *eth_c = data;
  csock_stop(&eth_c->csock);

  if (eth_c->fd > 0) { /* clear socks */
    fd_close(eth_c->fd);
    (void)close(eth_c->fd);
  }

}

static int register_eth_conduit( const char ifname[IFNAMSIZ]
                               , void *arg )
{
  int err = 0;
  struct le *le;
  struct ifreq if_idx;
  struct eth_csock *eth_c;
  struct eth_module *eth_m = arg;

  struct ifreq if_mac;

  if (!eth_m)
    return EINVAL;

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


  if ((eth_c->fd = socket( AF_PACKET
                         , SOCK_RAW
                         , IPPROTO_RAW)) == -1) {
    err = EINVAL;
    goto out;
  }

  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, ifname, IFNAMSIZ-1);
  if (ioctl(eth_c->fd, SIOCGIFINDEX, &if_idx) < 0) {
    debug("ioctl:SIOCGIFINDEX\n");
    err = errno;
    goto out;
  }

  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, ifname, IFNAMSIZ-1);
  if (ioctl(eth_c->fd, SIOCGIFHWADDR, &if_mac) < 0) {
    debug("ioctl:SIOCGIFHWADDR\n");
    err = errno;
    goto out;
  }

  memcpy(eth_c->mac, &if_mac.ifr_hwaddr.sa_data, 6);

  eth_c->sll = (struct sockaddr_ll) {
       .sll_family = AF_PACKET
      ,.sll_halen = ETH_ALEN
      ,.sll_hatype = ARPHRD_ETHER
      ,.sll_ifindex = if_idx.ifr_ifindex
      ,.sll_pkttype = PACKET_OTHERHOST
      ,.sll_protocol = arch_htobe16(0xCF01)
  };

  if (bind( eth_c->fd
          , (struct sockaddr *) &eth_c->sll
          , sizeof(struct sockaddr_ll))) {
    debug("bind\n");
    err = errno;
    goto out;
  }

  err = net_sockopt_blocking_set(eth_c->fd, false);
  if (err) {
    debug("nonblock set: %m\n", err);
    goto out;
  }

  err = fd_listen( eth_c->fd
                 , FD_READ
                 , _eth_read_handler
                 , eth_c);

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
  err = re_regex(ifname, strlen(ifname), "eth[0-9]+", &num);
  if (err) {
    err = re_regex(ifname, strlen(ifname), "usb[0-9]+", &num);
    if (err) {
      return false;
    }
    /*error("%s is not an ethernet if! [%u]\n", ifname, err);*/
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
