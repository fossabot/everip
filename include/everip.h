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

#ifndef EVERIP_H__
#define EVERIP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "__arch.h"
#include "__wires.h"
#include "__labels.h"

#define EVERIP_VERSION "0.0.3"

#define EVERIP_VERSION_PROTOCOL 3

static inline bool everip_version_compat(uint32_t a, uint32_t b) {
	return (a == b);
}

/* super defines */

#define EVER_OUTWARD_MBE_POS (300)
#define EVER_OUTWARD_MBE_LENGTH (1500)

#define CAE_HEADER_LENGTH (76)
#define CAE_HEADER_CHAL_LENGTH (12)

#define CTRL_HEADER_LENGTH 4
#define CTRL_HEADER_ERRLENGTH 4
#define CTRL_HEADER_ERRLENGTHMIN (CTRL_HEADER_ERRLENGTH + RELAYMAP_HEADER_LENGTH + 4)
#define CTRL_HEADER_ERRLENGTHMAX 256

#define CTRL_ECODE_NONE                 0
#define CTRL_ECODE_MALFORMED_ADDRESS    1
#define CTRL_ECODE_FLOOD                2
#define CTRL_ECODE_LINK_LIMIT_EXCEEDED  3
#define CTRL_ECODE_OVERSIZE_MESSAGE     4
#define CTRL_ECODE_UNDERSIZE_MESSAGE    5
#define CTRL_ECODE_AUTHENTICATION       6
#define CTRL_ECODE_INVALID              7
#define CTRL_ECODE_UNDELIVERABLE        8
#define CTRL_ECODE_LOOP_ROUTE           9
#define CTRL_ECODE_RETURN_PATH_INVALID 10

#define CTRL_TYPE_ERROR (2)
#define CTRL_TYPE_ERROR_be arch_htobe16(CTRL_TYPE_ERROR)

#define CTRL_TYPE_PING (3)
#define CTRL_TYPE_PING_be arch_htobe16(CTRL_TYPE_PING)
#define CTRL_TYPE_PINGKEY (5)
#define CTRL_TYPE_PINGKEY_be arch_htobe16(CTRL_TYPE_PINGKEY)

#define CTRL_TYPE_PONG (4)
#define CTRL_TYPE_PONG_be arch_htobe16(CTRL_TYPE_PONG)
#define CTRL_TYPE_PONGKEY (6)
#define CTRL_TYPE_PONGKEY_be arch_htobe16(CTRL_TYPE_PONGKEY)

/* bencode */

enum bencode_typ {
	BENCODE_STRING,
	BENCODE_INT,
	BENCODE_NULL,
};

struct bencode_value {
	union {
		struct pl pl;
		int64_t integer;
	} v;
	enum bencode_typ type;
};

struct bencode_handlers;

typedef int (bencode_object_entry_h)(const char *name,
				  const struct bencode_value *value, void *arg);
typedef int (bencode_array_entry_h)(unsigned idx,
				 const struct bencode_value *value, void *arg);
typedef int (bencode_object_h)(const char *name, unsigned idx,
			    struct bencode_handlers *h);
typedef int (bencode_array_h)(const char *name, unsigned idx,
			   struct bencode_handlers *h);

struct bencode_handlers {
	bencode_object_h *oh;
	bencode_array_h *ah;
	bencode_object_entry_h *oeh;
	bencode_array_entry_h *aeh;
	void *arg;
};

int bencode_decode(const char *str, size_t len, unsigned maxdepth,
		bencode_object_h *oh, bencode_array_h *ah,
		bencode_object_entry_h *oeh, bencode_array_entry_h *aeh, void *arg);

int bencode_decode_odict(struct odict **op, uint32_t hash_size, const char *str,
		      size_t len, unsigned maxdepth);
int bencode_encode_odict(struct re_printf *pf, const struct odict *o);

/*
 * Address
 */

#define ADDR_KEY_SIZE 32
#define ADDR_NETWORK_ADDR_SIZE 8
#define ADDR_SEARCH_TARGET_SIZE 16
#define ADDR_SERIALIZED_SIZE 40

struct PACKONE addr
{
    uint32_t protover;
    uint32_t padding;/** unused */
    union {
        struct {
            uint32_t three_be;
            uint32_t four_be;
            uint32_t one_be;
            uint32_t two_be;
        } ints;
        struct {
            uint64_t two_be;
            uint64_t one_be;
        } longs;
        uint8_t bytes[ADDR_SEARCH_TARGET_SIZE];
    } ip6;
    uint8_t key[ADDR_KEY_SIZE];
    uint64_t path;
};

int addr_calc_isvalid(const uint8_t address[16]);
int addr_calc_pubkeyaddr( uint8_t out_address[16], const uint8_t key[32] );

uint32_t addr_ip6_prefix(uint8_t ip6[16]);
uint32_t addr_prefix(struct addr *addr);

int addr_base32_decode( uint8_t* out , const uint32_t olen , const uint8_t* in , const uint32_t ilen );
int addr_base32_encode( uint8_t* out , const uint32_t olen , const uint8_t* in , const uint32_t ilen );

/*
 * Conduits
 */

struct csock;

struct PACKONE mbuf_ext {
	uint16_t c; /* content */
	uint16_t h; /* header */
	uint16_t e; /* entry */
	uint16_t s; /* scratch start */
};

/* outside address */

#define csock_addr_cpycsa(mb, new_csaddr) \
	{ \
	mbuf_set_pos(mb, 0); \
	struct csock_addr *__csaddr = (struct csock_addr *)mbuf_buf( (mb) ); \
	/*memset(csaddr, 0, sizeof(struct csock_addr));*/ \
	/*debug("(new_csaddr)->len = %u|%u\n", (new_csaddr)->len, (new_csaddr)->a.sa.len);*/ \
	memcpy(__csaddr, (new_csaddr), sizeof(struct csock_addr)); \
	}

struct PACKONE csock_addr {
	#define CSOCK_ADDR_LENTOP (4+2+2)
	#define CSOCK_ADDR_LENMAC (CSOCK_ADDR_LENTOP+6)
	uint32_t hash;
	uint16_t len;
    #define CSOCK_ADDR_BCAST  1
    #define CSOCK_ADDR_MAC    (1<<1)
    uint16_t flags;
	union {
		struct sa sa;
		uint8_t mac[6];
	} a;
};

struct PACKONE rmap_wireheader
{
    uint64_t label_be;
    uint8_t cas;
    uint8_t val;
    uint16_t penalty_be;
};
#define RELAYMAP_HEADER_LENGTH (12)
ASSERT_COMPILETIME(RELAYMAP_HEADER_LENGTH == sizeof(struct rmap_wireheader));

static inline void _wireheader_setversion(struct rmap_wireheader *w, uint8_t v)
{
    ASSERT_TRUE(v < 4);
    w->val = (v << 6) | (w->val & ((1<<(6))-1));
}

static inline void _wireheader_setshift(struct rmap_wireheader *w, uint32_t s)
{
    ASSERT_TRUE(s < 64);
    w->val = w->val >> 6 << 6;
    w->val |= s;
}

static inline uint32_t _wireheader_getshift(struct rmap_wireheader *w)
{
    return w->val & ((1<<(6))-1);
}

static inline void _wireheader_setcongestion(struct rmap_wireheader *w, uint32_t c)
{
    ASSERT_TRUE(c <= 127);
    if (!c) { c++; }
    w->cas = (w->cas & 1) | (c << 1);
}

static inline void _wireheader_setpenalty(struct rmap_wireheader *w, uint16_t p)
{
    w->penalty_be = arch_htobe16(p);
}

static inline void _wireheader_setsuppresson(struct rmap_wireheader *w, bool s)
{
    w->cas = w->cas >> 1 << 1;
    w->cas |= s;
}

struct PACKONE sess_wireheader
{
    uint8_t pubkey[32];

    struct rmap_wireheader sh;

    uint32_t version_be;

    #define SESS_WIREHEADER_flags_INCOMING 1
    #define SESS_WIREHEADER_flags_CTRLMSG (1<<1)
    uint8_t flags;

    uint8_t u; /* UNUSED... */
    uint16_t uu; /* UNUSED... */

    uint8_t ip6[16];
};
#define SESS_WIREHEADER_LENGTH (56 + RELAYMAP_HEADER_LENGTH)
ASSERT_COMPILETIME(SESS_WIREHEADER_LENGTH == sizeof(struct sess_wireheader));

/*
[uint32 content_options][content]
*/
typedef struct csock *(csock_send_h)(struct csock *csock, struct mbuf *mb);

struct csock {
	csock_send_h *send;
	struct csock *adj;
};

/** Defines a conduit */
struct conduit {
	struct csock csock; /* must be on top */
	struct conduits *ctx;

	uint8_t id; /* for relaymap */

	struct le le;

	char *name;
	char *desc;
	int state;

	/*beacon_func*/

};

struct conduits;
struct cd_relaymap;
struct cd_cmdcenter;
struct magi_eventdriver;

int conduits_init( struct conduits **conduitsp , struct cd_relaymap *relaymap , struct cd_cmdcenter *cmdcenter , struct magi_eventdriver *eventdriver );
int conduits_register(struct conduits *conduits, const char *name, const char *desc, struct csock *csock);
struct conduit *conduit_find(const struct conduits *conduits,
		       const struct conduit *conduit);

struct conduit_peer *conduits_peer_find( const struct conduits *conduits
					         		   , const struct csock_addr *csaddr );

int conduits_peer_ping(struct conduit_peer *p);

int conduits_peer_bootstrap( struct conduit *conduit
						   , struct conduits *c
						   , bool outside_initiation
						   , const uint8_t *remote_pubkey
						   , const struct csock_addr *csaddr
						   , const char *pword
						   , const char *login
						   , const char *identifier );

int conduits_debug(struct re_printf *pf, const struct conduits *conduits);

#define container_of(p, t, m) \
    (__extension__ ({                                                          \
        const __typeof__(((t*)0)->m)*__mp = (p); \
        (t*)((void*)(char*)__mp - offsetof(t, m)); \
    }))

static inline void csock_forward(struct csock *csock, struct mbuf *mb)
{
    do {
        struct csock* adj = csock->adj;
        csock = adj->send(adj, mb);
    } while (csock);
}

static inline struct csock *csock_next(struct csock *csock, struct mbuf *mb)
{
	if (!csock || !csock->adj) return NULL;
	csock_forward(csock, mb);
	return NULL;
}

/* used for call loops */
#define CSOCK_CALL(f, ctx, mb) \
    do {                                          \
        struct csock* out_cs = f(ctx, mb);		  \
        if (out_cs) { csock_next(out_cs, mb); }   \
    } while (0)


static inline void csock_flow(struct csock *c_a, struct csock *c_b)
{
	if (!c_a || !c_b) return;
    c_a->adj = c_b;
    c_b->adj = c_a;
}

static inline void csock_stop(struct csock *c)
{
	if (!c) return;
	if (c->adj) {
		c->adj->adj = NULL;
	}
	c->adj = NULL;
}

/*
 * MAGI
 */

struct magi_eventdriver {
	struct csock virtual_cs;
	struct list csocks[EVD_STAR__TOO_HIGH - EVD_STAR__TOO_LOW];
	struct list starfinders;

	uint8_t pubkey[32];
};

struct magi_starfinder {
	struct csock eventd_cs;
	struct tmr tmr;

    #define STARFINDER_STATE_INITIALIZING 0
    #define STARFINDER_STATE_RUNNING 1
    uint8_t state;

    uint8_t pathchangeinterval;

    void *lua;

    struct udp_sock *us; /* TEMPORARY */

    struct list endnodes;

    void *for_ping_resp; /* this is so ugly... */

};

int magi_eventdriver_init( struct magi_eventdriver **eventdp, uint8_t public_key[32] );
void magi_eventdriver_register_core( struct magi_eventdriver *eventd , struct csock *csock , enum EVD_STAR ep );
void magi_eventdriver_register_star( struct magi_eventdriver *eventd , struct csock *csock );
int magi_starfinder_init( struct magi_starfinder **starfinderp, uint8_t publickey[32] );

/*
 * Crypto
 */

#if 0
struct PACKONE cae_header
{
    uint32_t a;
    struct {
	    uint8_t a;
	    uint8_t b[7];
	    uint16_t c;
	    uint16_t d;
    } b;
    uint8_t c[24];
    uint8_t d[32];
    uint8_t e[16];
    uint8_t f[32];
};
ASSERT_COMPILETIME(CAE_HEADER_LENGTH == sizeof(struct cae_header));
#endif

struct caengine {
	uint8_t my_ipv6[16];
	uint8_t my_pubkey[32];
	uint8_t my_prvkey[32];
	struct list sessions;
	struct list authtokens;
};

struct caengine_authtoken {
	struct le le;

	char *login;
	char *pword;

	uint8_t secret[32];
	uint8_t uhash[8];
	uint8_t phash[8];
};

struct caengine_replay_guard {
	uint8_t hi;
};

enum session_nonce {
    SESSION_NONCE_HELLO = 0,
    SESSION_NONCE_REPEAT_HELLO = 1,
    SESSION_NONCE_KEY = 2,
    SESSION_NONCE_REPEAT_KEY = 3,
    SESSION_NONCE_FIRST_TRAFFIC_PACKET = 4
};

enum CAENGINE_STATE {
    CAENGINE_STATE_INIT = 0,
    CAENGINE_STATE_SENT_HELLO = 1,
    CAENGINE_STATE_RECEIVED_HELLO = 2,
    CAENGINE_STATE_SENT_KEY = 3,
    CAENGINE_STATE_RECEIVED_KEY = 4,
    CAENGINE_STATE_ESTABLISHED = 100
};

struct caengine_session {
	struct le le;
	struct caengine *ctx;

	uint8_t remote_ip6[16];

	uint64_t lastpkt_ts;
	uint64_t seconds_to_reset;

	struct caengine_replay_guard replay_guard;

	char *login;
    char *pword;
    int auth_type : 8;

	bool established : 1;
	char *dbg;

	/**/
	uint32_t nonceid;
	bool has_sk : 1;
	uint8_t shared_key[32];
	uint8_t remote_pubkey[32];

};


enum CAENGINE_DECRYPTERR {
    CAENGINE_DECRYPTERR_NONE = 0,
    CAENGINE_DECRYPTERR_RUNT = 1,
    CAENGINE_DECRYPTERR_NO_SESSION = 2,
    CAENGINE_DECRYPTERR_FINAL_SHAKE_FAIL = 3,
    CAENGINE_DECRYPTERR_FAILED_DECRYPT_RUN_MSG = 4,
    CAENGINE_DECRYPTERR_KEY_PKT_ESTABLISHED_SESSION = 5,
    CAENGINE_DECRYPTERR_WRONG_PERM_PUBKEY = 6,
    CAENGINE_DECRYPTERR_IP_RESTRICTED = 7,
    CAENGINE_DECRYPTERR_AUTH_REQUIRED = 8,
    CAENGINE_DECRYPTERR_UNRECOGNIZED_AUTH = 9,
    CAENGINE_DECRYPTERR_STRAY_KEY = 10,
    CAENGINE_DECRYPTERR_HANDSHAKE_DECRYPT_FAILED = 11,
    CAENGINE_DECRYPTERR_WISEGUY = 12,
    CAENGINE_DECRYPTERR_INVALID_PACKET = 13,
    CAENGINE_DECRYPTERR_REPLAY = 14,
    CAENGINE_DECRYPTERR_DECRYPT = 15
};

int caengine_init( struct caengine **caenginep
				 , const uint8_t private_key[32] );

int caengine_authtoken_add( struct caengine *caengine
                          , const char *login
                          , const char *pword );

/* X:S session */
int caengine_session_new( struct caengine_session **sessionp
					    , struct caengine *c
					    , const uint8_t remote_pubkey[32]
					    , const bool req_auth );
enum CAENGINE_DECRYPTERR caengine_session_decrypt(struct caengine_session *session, struct mbuf *mb);
int caengine_session_encrypt(struct caengine_session *session, struct mbuf *mb);
enum CAENGINE_STATE caengine_session_state(struct caengine_session *session);
void caengine_session_reset(struct caengine_session *session);
void caengine_session_resetiftimedout(struct caengine_session *session);
void caengine_session_setdbg(struct caengine_session *session, const char *name);
void caengine_session_setauth( struct caengine_session *session , const char *pword , const char *login );
/* X:E session */

int caengine_keys_parse(struct pl *key, uint8_t out[32]);
int caengine_keys_tostr(char **outp, uint8_t key[32]);
int caengine_address_validity(const uint8_t address[16]);
int caengine_address_frompubkey(uint8_t out[16], const uint8_t in[32]);

/*
 * Pinger
 */

typedef void (mrpinger_pong_h)(struct pl *_pl, uint32_t version, uint64_t ttl, void *userdata);
typedef void (mrpinger_ping_h)(uint32_t hashid, uint64_t cookie, void *userdata);


struct mrpinger {
	struct hash *clocks;
};

struct mrpinger_clock {
	struct le le;
	struct tmr tmr;

	uint32_t hashid;
	uint64_t cookie;

	uint64_t time_sent;
	uint64_t time_delay;

	mrpinger_pong_h *cb_pong;
	mrpinger_ping_h *cb_ping;

	void *userdata;

};

int mrpinger_init( struct mrpinger **mrpingerp );
int mrpinger_ping( struct mrpinger *pinger
				 , uint64_t delay
				 , mrpinger_pong_h *cb_pong
				 , mrpinger_ping_h *cb_ping
				 , void *userdata );

int mrpinger_pong( struct mrpinger *pinger
				 , uint32_t version
				 , struct pl *_pl );

/*
 * Conduit Peer
 */

enum CONDUIT_PEERSTATE
{
    CONDUIT_PEERSTATE_INIT = CAENGINE_STATE_INIT,
    CONDUIT_PEERSTATE_SENT_HELLO = CAENGINE_STATE_SENT_HELLO,
    CONDUIT_PEERSTATE_RECEIVED_HELLO = CAENGINE_STATE_RECEIVED_HELLO,
    CONDUIT_PEERSTATE_SENT_KEY = CAENGINE_STATE_SENT_KEY,
    CONDUIT_PEERSTATE_RECEIVED_KEY = CAENGINE_STATE_RECEIVED_KEY,
    CONDUIT_PEERSTATE_ESTABLISHED = CAENGINE_STATE_ESTABLISHED,
    CONDUIT_PEERSTATE_UNRESPONSIVE = -1,
    CONDUIT_PEERSTATE_UNAUTHENTICATED = -2,
};

struct conduit_peer {
	struct csock relaymap_cs;
	struct le le;
	struct le le_all;
	struct conduit *conduit;

	struct csock_addr csaddr;
	struct addr addr;

	struct caengine_session *caes;

	enum CONDUIT_PEERSTATE state;

	uint64_t lastmsg_ts;
	uint64_t lastping_ts;

	uint32_t cnt_ping;

	uint64_t bytes_in;
	uint64_t bytes_out;

	bool outside_initiation;
};

/*
 * GeoFront
 */

struct geofront
{
	uint8_t gendo;
};

int geofront_init( struct geofront **geofrontp );

/*
 * Terminal Dogma
 */

struct tmldogma {
    struct csock ctrdogma_cs;
    struct csock tunadapt_cs;
    struct csock eventd_cs;

    uint8_t ip6[16];
};

int tmldogma_init( struct tmldogma **tmldogmap , struct magi_eventdriver *eventd, uint8_t ip6[16] );

/*
 * Central Dogma
 */

#define RELAYMAP_SLOT_MAX (254)

enum RELAYMAP_SLOT_STATE {
     RELAYMAP_SLOT_STATE_WIPE = 0
    ,RELAYMAP_SLOT_STATE_DOWN = 1
    ,RELAYMAP_SLOT_STATE_ISUP = 2
    ,RELAYMAP_SLOT_STATE_CEIL = 3
};

struct cd_relaymap;

struct cd_relaymap_slot {
	struct csock csock;
	enum RELAYMAP_SLOT_STATE state;
	struct cd_relaymap *map;
};

struct cd_relaymap {
	struct csock *router_cs;
	struct cd_relaymap_slot slots[ RELAYMAP_SLOT_MAX ];
	/* X:S pinger */
	/* X:E pinger */
};

struct cd_manager {
	struct csock relaymap_cs;
	struct csock cmdcenter_cs;
	struct csock terminaldogma_cs;
	struct csock eventd_cs;

	struct hash *sessions;
};

struct cd_cmdcenter {
    struct csock manager_cs;
    struct csock rpinger_cs;

	uint8_t local_pubkey[32];
};

int cd_relaymap_init( struct cd_relaymap **relaymapp );
void cd_relaymap_slot_setstate( struct cd_relaymap_slot *slot , enum RELAYMAP_SLOT_STATE state );
int cd_relaymap_slot_add( uint64_t* out_label , struct cd_relaymap *map , struct csock *csock );
void cd_relaymap_slot_setstate( struct cd_relaymap_slot *slot, enum RELAYMAP_SLOT_STATE state );

int cd_cmdcenter_init( struct cd_cmdcenter **cmdcenterp, const uint8_t local_pubkey[32]);
struct csock *cd_cmdcenter_sendcmd( struct cd_cmdcenter *cmdcenter, struct mbuf *mb );

int cd_manager_init( struct cd_manager **managerp, struct magi_eventdriver *eventd );

/*
 * TUN
 */

#define TUN_IFNAMSIZ (16)

struct tunif {
	struct csock tmldogma_cs;
	int fd;
	char name[TUN_IFNAMSIZ];
};

int tunif_init( struct tunif **tunifp );

/*
 * Licenser
 */

struct licenser;
int licenser_alloc(struct licenser **licenserp, const char *filename);
int licenser_authenticate(struct licenser *l);

const char * licenser_buildversion_get(struct licenser *l);
int licenser_keyprivate_get(struct licenser *l, uint8_t privatekey[32]);
const char * licenser_keypublic_get(struct licenser *l);

typedef void (licenser_conduits_cycle_h)(struct odict *bootstrap);

int licenser_conduits_cycle(struct licenser *l, const char *key, licenser_conduits_cycle_h handler);

/*
 * Tree of Life
 */

struct treeoflife;
struct treeoflife_node;

typedef void (treeoflife_treemsg_h)( struct treeoflife *t
								   , uint32_t to
								   , struct odict *omsg);

int treeoflife_init( struct treeoflife **treeoflifep );
struct list *treeoflife_children_get( struct treeoflife *t );
void treeoflife_register_cb(struct treeoflife *t, treeoflife_treemsg_h *cb);
void treeoflife_msg_recv( struct treeoflife *t , struct odict *o);
int treeoflife_debug(struct re_printf *pf, const struct treeoflife *t);
uint32_t treeoflife_get_id( struct treeoflife *t );

/*
 * Modules
 */

#ifdef STATIC
#define DECL_EXPORTS(name) exports_ ##name
#else
#define DECL_EXPORTS(name) exports
#endif

int module_preload(const char *module);
void module_app_unload(void);

#ifndef NET_MAX_NS
#define NET_MAX_NS (4)
#endif

/*
 * Log
 */

enum log_level {
	LEVEL_DEBUG = 0,
	LEVEL_INFO,
	LEVEL_WARN,
	LEVEL_ERROR,
};

typedef void (log_h)(uint32_t level, const char *msg);

struct log {
	struct le le;
	log_h *h;
};

void log_register_handler(struct log *logh);
void log_unregister_handler(struct log *logh);
void log_enable_debug(bool enable);
void log_enable_info(bool enable);
void log_enable_stderr(bool enable);
void vlog(enum log_level level, const char *fmt, va_list ap);
void loglv(enum log_level level, const char *fmt, ...);
void debug(const char *fmt, ...);
void info(const char *fmt, ...);
void warning(const char *fmt, ...);
void error(const char *fmt, ...);

/*
 * Net - Networking
 */

struct network;

typedef void (net_change_h)(void *arg);

int  net_alloc(struct network **netp);
int  net_use_nameserver(struct network *net, const struct sa *ns);
void net_change(struct network *net, uint32_t interval,
		net_change_h *ch, void *arg);
void net_force_change(struct network *net);
bool net_check(struct network *net);
int  net_af(const struct network *net);
int  net_debug(struct re_printf *pf, const struct network *net);
const struct sa *net_laddr_af(const struct network *net, int af);
const char      *net_domain(const struct network *net);
struct dnsc     *net_dnsc(const struct network *net);

struct netevent;
int netevent_init( struct netevent **neteventp );

/*
 * User Interface
 */

typedef int  (ui_output_h)(const char *str);

struct ui {
	struct le le;
	const char *name;
	ui_output_h *outputh;
};

void ui_register(struct ui *ui);
void ui_unregister(struct ui *ui);

void ui_reset(void);
void ui_input(char key);
void ui_input_key(char key, struct re_printf *pf);
void ui_input_str(const char *str);
int  ui_input_pl(struct re_printf *pf, const struct pl *pl);
void ui_output(const char *fmt, ...);
bool ui_isediting(void);
int  ui_password_prompt(char **passwordp);


/*
 * Command interface
 */

#define KEYCODE_NONE   (0x00)
#define KEYCODE_REL    (0x04)
#define KEYCODE_ESC    (0x1b)

enum {
	CMD_PRM  = (1<<0),
	CMD_PROG = (1<<1),

	CMD_IPRM = CMD_PRM | CMD_PROG,
};

struct cmd_arg {
	char key;
	char *prm;
	bool complete;
	void *data;
};

struct cmd {
	const char *name;
	char key;
	int flags;
	const char *desc;
	re_printf_h *h;
};

struct cmd_ctx;
struct commands;

int  cmd_init(struct commands **commandsp);
int  cmd_register(struct commands *commands,
		  const struct cmd *cmdv, size_t cmdc);
void cmd_unregister(struct commands *commands, const struct cmd *cmdv);
int  cmd_process(struct commands *commands, struct cmd_ctx **ctxp, char key,
		 struct re_printf *pf, void *data);
int  cmd_process_long(struct commands *commands, const char *str, size_t len,
		      struct re_printf *pf_resp, void *data);
int cmd_print(struct re_printf *pf, const struct commands *commands);
const struct cmd *cmd_find_long(const struct commands *commands,
				const char *name);
struct cmds *cmds_find(const struct commands *commands,
		       const struct cmd *cmdv);

#if defined (PATH_MAX)
#define FS_PATH_MAX PATH_MAX
#elif defined (_POSIX_PATH_MAX)
#define FS_PATH_MAX _POSIX_PATH_MAX
#else
#define FS_PATH_MAX 512
#endif

/*
 * EVER/IP instance
 */

int  everip_init(void);
void everip_close(void);
struct network *everip_network(void);
struct mrpinger *everip_mrpinger(void);
struct commands *everip_commands(void);
struct caengine *everip_caengine(void);
struct conduits *everip_conduits(void);

#ifdef __cplusplus
}
#endif


#endif /* EVERIP_H__ */
