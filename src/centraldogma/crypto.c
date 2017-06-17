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

/*
    ! WORK IN PROGRESS !
*/

#include <re.h>
#include <everip.h>
#include <string.h>

#include <sodium.h>

ASSERT_COMPILETIME(24 == crypto_box_NONCEBYTES);
ASSERT_COMPILETIME(16 == crypto_box_MACBYTES);


#define CAE_ASSERT_TRUE(x) if (!(x)) {BREAKPOINT;}

#define CAEDEBUG(wrapper, format, ...) \
    do {                                                                                 \
        debug("[%p][%s][N%d] " format "\n", (void*)(wrapper), ((wrapper)->dbg ? (wrapper)->dbg : ""), (wrapper)->nonceid, __VA_ARGS__); \
    } while (0)

#define CAEDEBUG0(wrapper, format) \
    CAEDEBUG(session, format "%s", "");

void caengine_session_setdbg(struct caengine_session *session, const char *name)
{
    if (!session) return;
    str_dup(&session->dbg, name);
}

int caengine_keys_parse(struct pl *key, uint8_t out[32])
{
    if (!key || key->l < 52) {
        return EINVAL;
    }
    if (key->p[52] != '.' || key->p[53] != 'k') {
        return EINVAL;
    }
    if (32 != addr_base32_decode(out, 32, (const uint8_t *)key->p, 52)) {
        return EINVAL;
    }
    return 0;
}

int caengine_address_frompubkey(uint8_t out[16], const uint8_t in[32])
{
    uint8_t hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash, in, 32);
    crypto_hash_sha512(hash, hash, crypto_hash_sha512_BYTES);
    if (NULL != out) {
        memcpy(out, hash, 16);
    }
    return out[0] == 0xFC;
}

void caengine_session_reset(struct caengine_session *session)
{
    session->nonceid = CAENGINE_STATE_INIT;

#if 1
    memset(session->shared_key, 0, 32);
#endif

    session->has_sk = false;
    session->established = false;

    /*memset(&session->replay_guard, 0, sizeof(struct caengine_replay_guard));*/
}

void caengine_session_resetiftimedout(struct caengine_session *session)
{

    if (session->nonceid == CAENGINE_STATE_SENT_HELLO) {
        return;
    }

    uint64_t now = (uint32_t)((long long)(tmr_jiffies())/1000);
    if (now - session->lastpkt_ts > session->seconds_to_reset) {
        CAEDEBUG0(session, "RESETTING SESSION;");
        session->lastpkt_ts = now;
        caengine_session_reset(session);
    }
}

int caengine_session_encrypt(struct caengine_session *session, struct mbuf *mb)
{

    bool flipflop;
    if (!session || !mb) {
        return EINVAL;
    }

    CAEDEBUG0(session, "caengine_session_encrypt");

    if (!session->has_sk) {
        (void)crypto_box_beforenm( session->shared_key
                           , session->remote_pubkey
                           , session->ctx->my_prvkey);
        session->has_sk = 1;
        error("ENC SHARED KEY[%W]\n", session->shared_key, 32);
    }

    /* here we should check for who should go first... */

    if (session->established) {
        session->nonceid++;
        flipflop = (session->remote_pubkey[0] >= session->ctx->my_pubkey[0]);
        union {
            uint32_t i[2];
            uint8_t b[24];
        } nuni = { .i = {0,0} };
        nuni.i[(flipflop?1:0)] = arch_htobe32(session->nonceid);
        CAEDEBUG(session, "NONCE[%W]", nuni.b, 24);
        /*[NONCE(4)][AUTH(16)][PAYLOAD]*/
        mbuf_advance(mb, -20);
        mbuf_write_u32(mb, arch_htobe32(session->nonceid));
        crypto_box_easy_afternm( mbuf_buf(mb)
                               , mbuf_buf(mb) + 16
                               , mbuf_get_left(mb) - 16
                               , nuni.b
                               , session->shared_key);
        mbuf_advance(mb, -4);
    } else {
        /* 4+32+24+16 == [NONCE(4)][PUBKEY(32)][NDATA(24)][AUTH(16)][PAYLOAD]*/
        mbuf_advance(mb, -76);
        mbuf_write_u32(mb, arch_htobe32(session->nonceid));
        mbuf_write_mem(mb, session->ctx->my_pubkey, 32);
        uint8_t *nonce = mbuf_buf(mb);
        randombytes_buf(nonce, 24);
        mbuf_advance(mb, 24);

        crypto_box_easy_afternm( mbuf_buf(mb)
                               , mbuf_buf(mb) + 16
                               , mbuf_get_left(mb) - 16
                               , nonce
                               , session->shared_key);

        mbuf_advance(mb, -(4+32+24));
    }

    return 0;
}

enum CAENGINE_DECRYPTERR caengine_session_decrypt(struct caengine_session *session, struct mbuf *mb)
{
    bool flipflop;
    if (!session || !mb) {
        return CAENGINE_DECRYPTERR_NO_SESSION;
    }

    CAEDEBUG0(session, "caengine_session_decrypt");

    if (mbuf_get_left(mb) < 4)
        return CAENGINE_DECRYPTERR_RUNT;

    uint32_t nonceid = arch_betoh32(mbuf_read_u32(mb));

    if (nonceid < 5 && session->established) {
        caengine_session_reset(session);
    }

    if (!session->has_sk) {
        (void)crypto_box_beforenm( session->shared_key
                           , session->remote_pubkey
                           , session->ctx->my_prvkey);
        session->has_sk = 1;
    }

    uint8_t *nonce_data;
    if (nonceid < 5) { /* setup proc */
        /* 32+24+16 == [PUBKEY(32)][NDATA(24)][AUTH(16)][PAYLOAD]*/
        if (mbuf_get_left(mb) < 72)
            return CAENGINE_DECRYPTERR_RUNT;
        mbuf_advance(mb, 32); /* skip PUBKEY */
        nonce_data = mbuf_buf(mb);
        mbuf_advance(mb, 24);
    } else {
        /*[AUTH(16)][PAYLOAD]*/
        if (mbuf_get_left(mb) < 16)
            return CAENGINE_DECRYPTERR_RUNT;
        flipflop = (session->remote_pubkey[0] >= session->ctx->my_pubkey[0]);
        union {
            uint32_t i[2];
            uint8_t b[24];
        } nuni = { .i = {0,0} };
        nuni.i[(flipflop?0:1)] = arch_htobe32(nonceid);
        nonce_data = nuni.b;
        CAEDEBUG(session, "NONCE[%W]", nonce_data, 24);
    }

    if (0 == crypto_box_open_easy_afternm( mbuf_buf(mb) + 16
                                , mbuf_buf(mb)
                                , mbuf_get_left(mb)
                                , nonce_data
                                , session->shared_key)) {
        session->nonceid = nonceid;
        session->nonceid++;
        if (session->nonceid >= 3) {
            session->nonceid = 5;
            session->established = true;
        }
    } else {
        return CAENGINE_DECRYPTERR_DECRYPT;
    }

    mbuf_advance(mb, 16);
    return 0;
}

enum CAENGINE_STATE caengine_session_state(struct caengine_session *session)
{
    if (!session) {
        return CAENGINE_STATE_INIT;
    }
    if (session->nonceid <= CAENGINE_STATE_RECEIVED_KEY) {
        return session->nonceid;
    }
    return (session->established) ? CAENGINE_STATE_ESTABLISHED : CAENGINE_STATE_RECEIVED_KEY;
}

static void caengine_session_destructor(void *data)
{
    struct caengine_session *s = data;
    (void)s;

    s->login = mem_deref(s->login);
    s->pword = mem_deref(s->pword);
    s->dbg = mem_deref(s->dbg);

    list_unlink(&s->le);

    /* clear all information */
    memset(data, 0, sizeof(*s));
}

int caengine_session_new( struct caengine_session **sessionp
                        , struct caengine *c
                        , const uint8_t remote_pubkey[32]
                        , const bool req_auth )
{

    int err = 0;
    struct caengine_session *session;

    if (!sessionp || !c || !remote_pubkey)
        return EINVAL;

    session = mem_zalloc(sizeof(*session), caengine_session_destructor);
    if (!c)
        return ENOMEM;

    caengine_session_reset(session); /* nen no tame */

    session->lastpkt_ts = (uint32_t)((long long)(tmr_jiffies())/1000);
    session->seconds_to_reset = 60; /* one minute longer on this planet */

    session->ctx = c;

    memcpy(session->remote_pubkey, remote_pubkey, 32);
    caengine_address_frompubkey(session->remote_ip6, remote_pubkey);

    list_append(&c->sessions, &session->le, session);

    *sessionp = session;

    return err;
}

static void caengine_destructor(void *data)
{
	struct caengine *c = data;
	list_flush(&c->sessions);
    list_flush(&c->authtokens);
}

int caengine_init( struct caengine **caenginep
				 , const uint8_t private_key[32] )
{
	struct caengine *c;

	if (!caenginep)
		return EINVAL;

	c = mem_zalloc(sizeof(*c), caengine_destructor);
	if (!c)
		return ENOMEM;

	list_init(&c->sessions);

    if (NULL == private_key) {
        rand_bytes(c->my_prvkey, 32);
    } else {
    	memcpy(c->my_prvkey, private_key, 32);
    }

#if 1
    crypto_scalarmult_base(c->my_pubkey, c->my_prvkey);

    /* calculate key */
    if (!caengine_address_frompubkey(c->my_ipv6, c->my_pubkey)) {
    	error("CAE: Invalid EVER/IP(R) detected! %w\n", c->my_ipv6, 16);
    	c = mem_deref(c);
    	return EINVAL;
    }
#endif

	*caenginep = c;

	return 0;
}
