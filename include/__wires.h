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

enum EIPCTYPES
{
     EIPCTYPES_IP6_HOP =       0
    ,EIPCTYPES_IP6_ICMP =      1
    ,EIPCTYPES_IP6_IGMP =      2
    ,EIPCTYPES_IP6_IPV4 =      4
    ,EIPCTYPES_IP6_TCP =       6
    ,EIPCTYPES_IP6_EGP =       8
    ,EIPCTYPES_IP6_PUP =       12
    ,EIPCTYPES_IP6_UDP =       17
    ,EIPCTYPES_IP6_IDP =       22
    ,EIPCTYPES_IP6_TP =        29
    ,EIPCTYPES_IP6_DCCP =      33
    ,EIPCTYPES_IP6_IPV6 =      41
    ,EIPCTYPES_IP6_RSVP =      46
    ,EIPCTYPES_IP6_GRE =       47
    ,EIPCTYPES_IP6_ESP =       50
    ,EIPCTYPES_IP6_AH =        51
    ,EIPCTYPES_IP6_ICMPV6 =    58
    ,EIPCTYPES_IP6_MTP =       92
    ,EIPCTYPES_IP6_BEETPH =    94
    ,EIPCTYPES_IP6_ENCAP =     98
    ,EIPCTYPES_IP6_PIM =       103
    ,EIPCTYPES_IP6_COMP =      108
    ,EIPCTYPES_IP6_SCTP =      132
    ,EIPCTYPES_IP6_UDPLITE =   136
    ,EIPCTYPES_IP6_MAX =       255

    ,EIPCTYPES_MAGI =          256

    ,EIPCTYPES_RESERVED =      258
    ,EIPCTYPES_RESERVED_MAX =  0x7fff

    ,EIPCTYPES_AVAILABLE =     0x8000

    ,EIPCTYPES_CTRL = 0xffff + 1
    ,EIPCTYPES_MAX = 0xffff + 2
};

struct wire_data {
    uint8_t vaf;
    uint8_t u;
    uint16_t ctype_be;
};
#define WIRE_DATA_LENGTH 4
ASSERT_COMPILETIME(sizeof(struct wire_data) == WIRE_DATA_LENGTH);

#define WIRE_DATA_LASTESTVERSION 1

static inline enum EIPCTYPES wire_data__ctype_get(struct wire_data* hdr)
{
    return arch_betoh16(hdr->ctype_be);
}

static inline void wire_data__ctype_set(struct wire_data* hdr, enum EIPCTYPES type)
{
    ASSERT_TRUE(type <= 0xffff);
    hdr->ctype_be = arch_htobe16(type);
}

static inline uint8_t wire_data__ver_get(struct wire_data* hdr)
{
    return hdr->vaf >> 4;
}

static inline void wire_data__ver_set(struct wire_data* hdr, uint8_t version)
{
    hdr->vaf = (hdr->vaf & 0x0f) | (version << 4);
}

/* eventdriver */

enum EVD_STAR {
     EVD_STAR__TOO_LOW = 511
    ,EVD_STAR_CONNECT = 512
    ,EVD_STAR_SUPERIORITY = 513
    ,EVD_STAR_NODE = 514
    ,EVD_STAR_SENDMSG = 515
    ,EVD_STAR_PING = 516
    ,EVD_STAR_PONG = 517
    ,EVD_STAR_SESSIONS = 518
    ,EVD_STAR_PEERS = 519
    ,EVD_STAR_PATHFINDERS = 520
    ,EVD_STAR__TOO_HIGH = 521
};

enum EVD_CORE {
     EVD_CORE__TOO_LOW = 1023
    ,EVD_CORE_CONNECT = 1024
    ,EVD_CORE_PATHFINDER = 1025
    ,EVD_CORE_PATHFINDER_GONE = 1026
    ,EVD_CORE_SWITCH_ERR = 1027
    ,EVD_CORE_SEARCH_REQ = 1028
    ,EVD_CORE_PEER = 1029
    ,EVD_CORE_PEER_GONE = 1030
    ,EVD_CORE_SESSION = 1031
    ,EVD_CORE_SESSION_ENDED = 1032
    ,EVD_CORE_DISCOVERED_PATH = 1033
    ,EVD_CORE_MSG = 1034
    ,EVD_CORE_PING = 1035
    ,EVD_CORE_PONG = 1036
    ,EVD_CORE__TOO_HIGH = 1037
};

#define EVD_CORE_MSG_LENGTH_MIN (SESS_WIREHEADER_LENGTH + 4)

struct wire_beacon {
    uint32_t ver_be;
    uint8_t pubkey[32];
};
#define WIRE_BEACON_LENGTH 36
ASSERT_COMPILETIME(sizeof(struct wire_beacon) == WIRE_BEACON_LENGTH);


struct wire_ethframe
{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} PACKONE;
#define WIRE_ETHFRAME_LENGTH 14
ASSERT_COMPILETIME(WIRE_ETHFRAME_LENGTH == sizeof(struct wire_ethframe));

