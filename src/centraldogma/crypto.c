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

#define CAE_ASSERT_TRUE(x) if (!(x)) {BREAKPOINT;}

#define CAEDEBUG(wrapper, format, ...) \
    do {                                                                                 \
        debug("[%p][%s][N%d] " format "\n", (void*)(wrapper), ((wrapper)->dbg ? (wrapper)->dbg : ""), (wrapper)->nonce_next, __VA_ARGS__); \
    } while (0)

#define CAEDEBUG0(wrapper, format) \
    CAEDEBUG(session, format "%s", "")

static enum CAENGINE_DECRYPTERR caengine_session_decrypt_handshake( struct caengine_session *session, struct mbuf *mb, uint32_t nonce);
static int caengine_session_encrypt_handshake( struct caengine_session *session, struct mbuf *mb );
static inline struct caengine_authtoken *caengine_authtoken_get( struct caengine *caengine , uint8_t chal_type , uint8_t chal_lookup[7] );

static inline int _message_hash_password( uint8_t out_secret[32]
                                        , uint8_t out_challenge[8]
                                        , const char* login
                                        , const char* pw
                                        , const uint8_t atype )
{
    if (!out_secret || !out_challenge || !pw) {
        return EINVAL;
    }
    crypto_hash_sha256(out_secret, (uint8_t*) pw, str_len(pw));
    uint8_t tmp[32];
    if (1 == atype) {
        crypto_hash_sha256(tmp, out_secret, 32);
        debug("The password [%s] = [%w]\n", pw, tmp, 8);
    } else if (2 == atype || login) {
        crypto_hash_sha256(tmp, (uint8_t*) login, str_len(login));
        debug("The password [%s] && login [%s] = [%w]\n", pw, login, tmp, 8);
    } else {
        return EINVAL;
    }
    tmp[0] = atype;
    memcpy(out_challenge, tmp, 8);
    return 0;
}

#if 0

static inline void _key_tostr(uint8_t output[65], uint8_t key[32])
{
    if (key) {
        re_snprintf((char *)output, 65, "%w", key, 32);
        return;
    }
    str_ncpy((char *)output, "NULL", 5);
}

static inline void _key_pub_tostr(uint8_t output[65], uint8_t privateKey[32])
{
    if (privateKey) {
        uint8_t publicKey[32];
        crypto_scalarmult_curve25519_base(publicKey, privateKey);
        _key_tostr(output, publicKey);
        return;
    }
    _key_tostr(output, NULL);
}
#endif

static inline void _calc_sharedsecret( uint8_t out_secret[32]
                                     , uint8_t local_prvkey[32]
                                     , uint8_t remote_pubkey[32]
                                     , uint8_t pwordhash[32])
{
    if (pwordhash == NULL) {
        (void)crypto_box_curve25519xsalsa20poly1305_beforenm( out_secret
                                                            , remote_pubkey
                                                            , local_prvkey);
    } else {
        union {
            struct {
                uint8_t k[32];
                uint8_t p[32];
            } c;
            uint8_t b[64];
        } b;

        (void)crypto_scalarmult_curve25519(b.c.k, local_prvkey, remote_pubkey);
        memcpy(b.c.p, pwordhash, 32);
        crypto_hash_sha256(out_secret, b.b, 64);
    }

    uint8_t pubkey[32];
    crypto_scalarmult_curve25519_base(pubkey, local_prvkey);

    CAE_ASSERT_TRUE(memcmp(pubkey, remote_pubkey, 32));

#if 0
    re_printf("-----------------------\n");
    re_printf("local_prvkey  = %w\n", local_prvkey, 32);
    re_printf("remote_pubkey = %w\n", remote_pubkey, 32);
    re_printf("pwordhash     = %w\n", pwordhash, 32);
    re_printf("out_secret    = %w\n", out_secret, 32);
    re_printf("-----------------------\n");
#endif

}

static inline __attribute__ ((warn_unused_result))
int _decrypt_random_nonce( uint8_t nonce[24]
                         , struct mbuf *mb
                         , uint8_t secret[32] )
{
    if (mb->pos < 16) {
        BREAKPOINT;
    }

#if 0
    re_printf("DEC: nonce = %w\n", nonce, 24);
    re_printf("DEC: secret = %w\n", secret, 32);
    re_printf("DEC: mb->pos = %u\n", mb->pos);
    re_printf("DEC: mbuf_get_left = %u\n", mbuf_get_left(mb));
#endif

    uint8_t* startp = mbuf_buf(mb) - 16;
    uint8_t padding_buf[16];
    memcpy(padding_buf, startp, 16);
    memset(startp, 0, 16);
    if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
            startp, startp, mbuf_get_left(mb) + 16, nonce, secret) != 0)
    {
        return EINVAL;
    }

    memcpy(startp, padding_buf, 16);

    mbuf_advance(mb, 16);

    return 0;
}

static inline __attribute__ ((warn_unused_result))
int _encrypt_random_nonce( uint8_t nonce[24]
                         , struct mbuf *mb
                         , uint8_t secret[32] )
{
    if (!mb)
        return EINVAL;

    if (mb->pos < 32) {
        BREAKPOINT;
    }

#if 0
    re_printf("ENC: nonce = %w\n", nonce, 24);
    re_printf("ENC: secret = %w\n", secret, 32);
    re_printf("ENC: mb->pos = %u\n", mb->pos);
    re_printf("ENC: mbuf_get_left = %u\n", mbuf_get_left(mb));
#endif

    uint8_t* startp = mbuf_buf(mb) - 32;
    uint8_t padding_buf[16];
    memcpy(padding_buf, startp, 16);
    memset(startp, 0, 32);
    crypto_box_curve25519xsalsa20poly1305_afternm(
        startp, startp, mbuf_get_left(mb) + 32, nonce, secret);

    memcpy(startp, padding_buf, 16);

    mbuf_advance(mb, -16);

    return 0;
}

/**/
/**/

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

int caengine_keys_tostr(char **outp, uint8_t key[32])
{
    char *out;

    out = mem_zalloc(54, NULL);
    if (!out) {
        return ENOMEM;
    }
    /*Base32_encode((uint8_t*)out->bytes, 53, key, 32);*/
    out[52] = '.';
    out[53] = 'k';

    *outp = out;

    return 0;
}

int caengine_address_validity(const uint8_t address[16])
{
    return address[0] == 0xFC;
}

int caengine_address_frompubkey(uint8_t out[16], const uint8_t in[32])
{
    uint8_t hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash, in, 32);
    crypto_hash_sha512(hash, hash, crypto_hash_sha512_BYTES);
    if (NULL != out) {
        memcpy(out, hash, 16);
    }
    return caengine_address_validity( out );
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

void caengine_session_reset(struct caengine_session *session)
{
    session->nonce_next = CAENGINE_STATE_INIT;
    session->is_initiator = false;

    memset(session->local_tmp_prvkey, 0, 32);
    memset(session->local_tmp_pubkey, 0, 32);
    memset(session->remote_tmp_pubkey, 0, 32);
    memset(session->sharedsecretkey, 0, 32);
    session->established = false;

    /*memset(&session->replay_guard, 0, sizeof(struct caengine_replay_guard));*/
}

void caengine_session_resetiftimedout(struct caengine_session *session)
{

    if (session->nonce_next == CAENGINE_STATE_SENT_HELLO) {
        return;
    }

    uint64_t now = (uint32_t)((long long)(tmr_jiffies())/1000);
    if (now - session->lastpkt_ts > session->seconds_to_reset) {
        CAEDEBUG0(session, "RESETTING SESSION;");
        session->lastpkt_ts = now;
        caengine_session_reset(session);
    }
}

void caengine_session_setdbg(struct caengine_session *session, const char *name)
{
    if (!session) return;
    str_dup(&session->dbg, name);
}

void caengine_session_setauth( struct caengine_session *session
                             , const char *pword
                             , const char *login )
{
    if (!session) return;

    if (!pword && (session->pword || session->auth_type)) {
        session->pword = mem_deref(session->pword);
        session->auth_type = 0;
    } else if (!session->pword || strcmp(session->pword, pword)) {
        session->login = mem_deref(session->login);
        session->pword = mem_deref(session->pword);
        str_dup(&session->pword, pword);
        session->auth_type = 1;
        if (login) {
            session->auth_type = 2;
            str_dup(&session->login, login);
        }
    } else {
        return;
    }
    /* new auth terms, so we need to reset */
    caengine_session_reset(session);
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
    session->req_auth = req_auth;

    list_append(&c->sessions, &session->le, session);

    *sessionp = session;

    return err;
}

static inline enum CAENGINE_DECRYPTERR caengine_message_decrypt( struct caengine_session *session
                                                               , uint32_t nonce
                                                               , struct mbuf *mb
                                                               , uint8_t secret[32] )
{
    union {
        uint32_t i[2];
        uint8_t b[24];
    } nonce_cast = { .i = {0, 0} };
    nonce_cast.i[!session->is_initiator] = arch_htole32( nonce );

    if (_decrypt_random_nonce(nonce_cast.b, mb, secret)) {
        warning("DROP authenticated decryption failed\n");
        return CAENGINE_DECRYPTERR_DECRYPT;
    }

    return 0;
}


static inline int caengine_message_encrypt(struct caengine_session *session
                                          , uint32_t nonce
                                          , struct mbuf *mb
                                          , uint8_t secret[32] )
{
    int err = 0;
    union {
        uint32_t i[2];
        uint8_t b[24];
    } nonce_cast = { .i = {0, 0} };
    nonce_cast.i[session->is_initiator] = sys_htoll( nonce );

    err = _encrypt_random_nonce(nonce_cast.b, mb, secret);
    if (err) {
        warning("Authenticated encryption failed\n");
        goto out;
    }

out:
    return err;
}

static inline void caengine_session_updatets(struct caengine_session *session, struct mbuf *mb)
{
    session->lastpkt_ts = (uint32_t)((long long)(tmr_jiffies())/1000);
}

static enum CAENGINE_DECRYPTERR caengine_session_decrypt_handshake( struct caengine_session *session
                                                                  , struct mbuf *mb
                                                                  , uint32_t nonce )
{
    if (!session || !mb || is_allzero(session->remote_pubkey, 32)) {
        return CAENGINE_DECRYPTERR_NO_SESSION;
    }

    CAEDEBUG0(session, "caengine_session_decrypt_handshake");

    if (mbuf_get_left(mb) < CAE_HEADER_LENGTH) {
        CAEDEBUG0(session, "DROP runt");
        return CAENGINE_DECRYPTERR_RUNT;
    }

    size_t mb_top = mb->pos;

    uint8_t chal_type;
    uint8_t chal_lookup[8] = {0};
    uint16_t chal_authdevcount;
    uint16_t chal_additional;

    uint8_t hsnonce[24] = {0};
    uint8_t pubkey[32] = {0};
    uint8_t enctmpkey[32] = {0};

    /*chal_type = mbuf_read_u8(mb);*/
    mbuf_read_mem(mb, chal_lookup, 8);
    chal_type = chal_lookup[0];
    chal_authdevcount = ntohs(mbuf_read_u16(mb));
    chal_additional = ntohs(mbuf_read_u16(mb));
    mbuf_read_mem(mb, hsnonce, 24);
    mbuf_read_mem(mb, pubkey, 32);

#if 0
    re_printf("nonce = %u\n", nonce);
    re_printf("chal_type = %u\n", chal_type);
    re_printf("chal_lookup = %w\n", chal_lookup, 7);
    re_printf("chal_authdevcount = %u\n",chal_authdevcount);
    re_printf("chal_additional = %u\n", chal_additional);
    re_printf("hnonce = %w\n", hsnonce, 24);
    re_printf("pubkey = %w\n", pubkey, 32);
    /*re_printf("auth = %w\n", auth, 16);*/
#endif

    if (memcmp(session->remote_pubkey, pubkey, 32)) {
        return CAENGINE_DECRYPTERR_WRONG_PERM_PUBKEY;
    }

    if(!((session->nonce_next < CAENGINE_STATE_RECEIVED_HELLO) ==
                    is_allzero(session->remote_tmp_pubkey, 32))) {
        BREAKPOINT;
    }


    uint8_t* pwhash = NULL;

    struct caengine_authtoken *atoken = \
        caengine_authtoken_get( session->ctx
                              , chal_type
                              , chal_lookup );

    if (atoken) {
        pwhash = atoken->secret;
    } else {
        if (session->req_auth) {
            CAEDEBUG0(session, "DROP: CAENGINE_DECRYPTERR_AUTH_REQUIRED");
            return CAENGINE_DECRYPTERR_AUTH_REQUIRED;
        } else if (chal_type != 0) {
            CAEDEBUG0(session, "DROP: CAENGINE_DECRYPTERR_UNRECOGNIZED_AUTH");
            return CAENGINE_DECRYPTERR_UNRECOGNIZED_AUTH;
        }
    }

    uint32_t nonce_next;
    uint8_t oursecretkey[32];

    if (nonce < SESSION_NONCE_KEY) {
        if (nonce == SESSION_NONCE_HELLO) {
            CAEDEBUG(session, "HELLO auth: %d",
                            (atoken != NULL));
        } else {
            CAE_ASSERT_TRUE(nonce == SESSION_NONCE_REPEAT_HELLO);
            CAEDEBUG0(session, "RECV: SESSION_NONCE_REPEAT_HELLO");
        }

        _calc_sharedsecret( oursecretkey
                          , session->ctx->my_prvkey
                          , session->remote_pubkey
                          , pwhash);
        nonce_next = CAENGINE_STATE_RECEIVED_HELLO;
    } else {
        if (nonce == SESSION_NONCE_KEY) {
            CAEDEBUG0(session, "RECV: SESSION_NONCE_KEY");
            /*BREAKPOINT;*/
        } else {
            CAE_ASSERT_TRUE(nonce == SESSION_NONCE_REPEAT_KEY);
            CAEDEBUG0(session, "RECV: SESSION_NONCE_REPEAT_KEY");
        }
        if (!session->is_initiator) {
            CAEDEBUG0(session, "DROP: CAENGINE_DECRYPTERR_STRAY_KEY");
            return CAENGINE_DECRYPTERR_STRAY_KEY;
        }

        _calc_sharedsecret(oursecretkey,
                        session->local_tmp_prvkey,
                        session->remote_pubkey,
                        pwhash);
        nonce_next = CAENGINE_STATE_RECEIVED_KEY;
    }

    if (_decrypt_random_nonce(hsnonce, mb, oursecretkey)) {
        mbuf_set_pos(mb, mb_top);
        mbuf_fill(mb, 0, mbuf_get_left(mb));
        return CAENGINE_DECRYPTERR_HANDSHAKE_DECRYPT_FAILED;
    }

    mbuf_read_mem(mb, enctmpkey, 32);

#if 0
    re_printf("enctmpkey = %w\n", enctmpkey, 32);
#endif

    if (is_allzero(enctmpkey, 32)) {
        CAEDEBUG0(session, "DROP: CAENGINE_DECRYPTERR_WISEGUY");
        return CAENGINE_DECRYPTERR_WISEGUY;
    }

    if (nonce == SESSION_NONCE_HELLO) {
        if (!memcmp(session->remote_tmp_pubkey, enctmpkey, 32)) {
            CAEDEBUG0(session, "DROP: CAENGINE_DECRYPTERR_INVALID_PACKET");
            return CAENGINE_DECRYPTERR_INVALID_PACKET;
        }
    } else if (nonce == SESSION_NONCE_KEY && session->nonce_next >= CAENGINE_STATE_RECEIVED_KEY) {
        if (!memcmp(session->remote_tmp_pubkey, enctmpkey, 32)) {
            CAE_ASSERT_TRUE(!is_allzero(session->remote_tmp_pubkey, 32));
            CAEDEBUG0(session, "DROP: CAENGINE_DECRYPTERR_INVALID_PACKET");
            return CAENGINE_DECRYPTERR_INVALID_PACKET;
        }

    } else if (nonce == SESSION_NONCE_REPEAT_KEY && session->nonce_next >= CAENGINE_STATE_RECEIVED_KEY) {
        if (memcmp(session->remote_tmp_pubkey, enctmpkey, 32)) {
            CAE_ASSERT_TRUE(!is_allzero(session->remote_tmp_pubkey, 32));
            CAEDEBUG0(session, "DROP: CAENGINE_DECRYPTERR_INVALID_PACKET");
            return CAENGINE_DECRYPTERR_INVALID_PACKET;
        }
    }

    if (nonce_next == CAENGINE_STATE_RECEIVED_KEY) {
        CAE_ASSERT_TRUE(nonce == SESSION_NONCE_KEY || nonce == SESSION_NONCE_REPEAT_KEY);
        switch (session->nonce_next) {
            case CAENGINE_STATE_INIT:
            case CAENGINE_STATE_RECEIVED_HELLO:
            case CAENGINE_STATE_SENT_KEY: {
                CAEDEBUG0(session, "DROP: CAENGINE_DECRYPTERR_STRAY_KEY");
                return CAENGINE_DECRYPTERR_STRAY_KEY;
            }
            case CAENGINE_STATE_SENT_HELLO: {
                memcpy(session->remote_tmp_pubkey, enctmpkey, 32);
                break;
            }
            case CAENGINE_STATE_RECEIVED_KEY: {
                if (nonce == SESSION_NONCE_KEY) {
                    memcpy(session->remote_tmp_pubkey, enctmpkey, 32);
                } else {
                    CAE_ASSERT_TRUE(!memcmp(session->remote_tmp_pubkey, enctmpkey, 32));
                }
                break;
            }
            default: {
                CAE_ASSERT_TRUE(!session->established);
                if (nonce == SESSION_NONCE_KEY) {
                    memcpy(session->remote_tmp_pubkey, enctmpkey, 32);
                    CAEDEBUG0(session, "NEW KEY; RECALC SSECRET");
                    _calc_sharedsecret(session->sharedsecretkey,
                                    session->local_tmp_prvkey,
                                    session->remote_tmp_pubkey,
                                    NULL);
                } else {
                    CAE_ASSERT_TRUE(!memcmp(session->remote_tmp_pubkey, enctmpkey, 32));
                }
                nonce_next = session->nonce_next + 1;
                CAEDEBUG0(session, "NEW KEY?");
            }
        }

    } else if (nonce_next == CAENGINE_STATE_RECEIVED_HELLO) {
        CAE_ASSERT_TRUE(nonce == SESSION_NONCE_HELLO || nonce == SESSION_NONCE_REPEAT_HELLO);
        if (memcmp(session->remote_tmp_pubkey, enctmpkey, 32)) {
            switch (session->nonce_next) {
                case CAENGINE_STATE_SENT_HELLO: {
                    if (memcmp(session->remote_pubkey, session->ctx->my_pubkey, 32) < 0)
                    {
                        CAEDEBUG0(session, "YOUR (REMOTES) PLANE!");
                        caengine_session_reset(session);
                        memcpy(session->remote_tmp_pubkey, enctmpkey, 32);
                        break;
                    } else {
                        CAEDEBUG0(session, "MY (LOCAL) PLANE!");
                        return 0;
                    }
                }
                case CAENGINE_STATE_INIT: {
                    memcpy(session->remote_tmp_pubkey, enctmpkey, 32);
                    break;
                }
                default: {
                    CAEDEBUG0(session, "RESET SESSION");
                    caengine_session_reset(session);
                    memcpy(session->remote_tmp_pubkey, enctmpkey, 32);
                    break;
                }
            }
        } else {
            switch (session->nonce_next) {
                case CAENGINE_STATE_RECEIVED_HELLO:
                case CAENGINE_STATE_SENT_KEY: {
                    nonce_next = session->nonce_next;
                    break;
                }
                default: {
                    CAEDEBUG0(session, "DROP: CAENGINE_DECRYPTERR_INVALID_PACKET");
                    return CAENGINE_DECRYPTERR_INVALID_PACKET;
                }
            }
        }
    } else {
        error("!!!UNREACHABLE!!!\n"); BREAKPOINT;
    }

    CAE_ASSERT_TRUE(session->nonce_next < nonce_next ||
        (session->nonce_next <= CAENGINE_STATE_RECEIVED_KEY && nonce_next == session->nonce_next)
    );
    session->nonce_next = nonce_next;

    return 0;
}

static int caengine_session_encrypt_handshake( struct caengine_session *session
                                             , struct mbuf *mb )
{

    uint8_t *hsnonce;

/*
    uint32_t nonce; OK

    uint8_t chal_type; OK
    uint8_t chal_lookup[7] = {0}; OK
    uint16_t chal_authdevcount; OK
    uint16_t chal_additional; OK

    uint8_t hsnonce[24] = {0}; ?
    uint8_t pubkey[32] = {0}; OK
    uint8_t auth[16] = {0};
    uint8_t enctmpkey[32] = {0};
*/

    if (!session || !mb || is_allzero(session->remote_pubkey, 32)) {
        return EINVAL;
    }

    CAEDEBUG0(session, "caengine_session_encrypt_handshake");

    mbuf_advance(mb, -(CAE_HEADER_LENGTH));

    mbuf_write_u32(mb, htonl(session->nonce_next));

    rand_bytes(mbuf_buf(mb), CAE_HEADER_CHAL_LENGTH + 24);

    CAE_ASSERT_TRUE(!is_allzero(session->remote_pubkey, 32));

    uint8_t* pw_hash = NULL;
    uint8_t pw_hash_buf[32];
    if (NULL == session->pword) {
        mbuf_write_u8(mb, session->auth_type);
        mbuf_advance(mb, 7 + 2);
        mbuf_write_u16(mb, 0); /*additional=0*/
    } else {
        /* the next function writes to mb */
        uint8_t chal_lookup[8];
        _message_hash_password( pw_hash_buf
                              , chal_lookup
                              , session->login
                              , session->pword
                              , session->auth_type );

        /*mbuf_write_u8(mb, session->auth_type);*/
        mbuf_write_mem(mb, chal_lookup, 8);
        mbuf_write_u32(mb, 0); /* derv and addition to 0 */

        pw_hash = pw_hash_buf;
    }

    hsnonce = mbuf_buf(mb);
    mbuf_advance(mb, 24); /* skip hsnonce */

    mbuf_write_mem(mb, session->ctx->my_pubkey, 32);

    mbuf_advance(mb, 16); /* skip authenticator */

    if (session->nonce_next == CAENGINE_STATE_INIT ||
        session->nonce_next == CAENGINE_STATE_RECEIVED_HELLO)
    {
        rand_bytes(session->local_tmp_prvkey, 32);
        crypto_scalarmult_curve25519_base(session->local_tmp_pubkey, session->local_tmp_prvkey);
    }

    mbuf_write_mem(mb, session->local_tmp_pubkey, 32); /* enc pub key */

    CAEDEBUG(session, "SEND: %s%s PKT",
                    ((session->nonce_next & 1) ? "REPEAT " : ""),
                    ((session->nonce_next < CAENGINE_STATE_RECEIVED_HELLO) ? "HELLO" : "KEY"));


    uint8_t secret[32];
    if (session->nonce_next < CAENGINE_STATE_RECEIVED_HELLO) {
        _calc_sharedsecret( secret
                       , session->ctx->my_prvkey
                       , session->remote_pubkey
                       , pw_hash );

        session->is_initiator = true;

        CAE_ASSERT_TRUE(session->nonce_next <= CAENGINE_STATE_SENT_HELLO);
        session->nonce_next = CAENGINE_STATE_SENT_HELLO;

    } else {
        _calc_sharedsecret( secret
                       , session->ctx->my_prvkey
                       , session->remote_tmp_pubkey
                       , pw_hash );

        CAE_ASSERT_TRUE(session->nonce_next <= CAENGINE_STATE_SENT_KEY);
        session->nonce_next = CAENGINE_STATE_SENT_KEY;
    }

    CAE_ASSERT_TRUE((session->nonce_next < CAENGINE_STATE_RECEIVED_HELLO) ==
                is_allzero(session->remote_tmp_pubkey, 32));

    mbuf_advance(mb, -32);
    int ret = _encrypt_random_nonce(hsnonce, mb, secret);
    mbuf_advance(mb, -(CAE_HEADER_LENGTH - 32 - 16));

    return ret;
}

enum CAENGINE_DECRYPTERR caengine_session_decrypt(struct caengine_session *session, struct mbuf *mb)
{
    if (!session || !mb) {
        return CAENGINE_DECRYPTERR_NO_SESSION;
    }

    if (mbuf_get_left(mb) < 20) {
        CAEDEBUG0(session, "DROP runt");
        return CAENGINE_DECRYPTERR_RUNT;
    }

    /*error("[ALL:DATA] %w\n", mb->buf, mb->size);*/
    /*re_printf("[DEC:DATA] %w\n", mbuf_buf(mb), mbuf_get_left(mb));*/

    uint32_t nonce = ntohl(mbuf_read_u32(mb));
    CAEDEBUG(session, "caengine_session_decrypt; nonce=%u", nonce);

    if (!session->established) {
        if (nonce >= SESSION_NONCE_FIRST_TRAFFIC_PACKET) {
            if (session->nonce_next < CAENGINE_STATE_SENT_KEY) {
                return CAENGINE_DECRYPTERR_NO_SESSION;
            }

            CAEDEBUG(session, "FINAL; nonce=%u", nonce);

            uint8_t secret[32];
            _calc_sharedsecret( secret
                           , session->local_tmp_prvkey
                           , session->remote_tmp_pubkey
                           , NULL );

            enum CAENGINE_DECRYPTERR ret = caengine_message_decrypt(session, nonce, mb, secret);

            if (!ret) {
                CAEDEBUG0(session, "FINAL: SUCCESS!");
                memcpy(session->sharedsecretkey, secret, 32);
                session->established = true;
                session->nonce_next += 3;
                caengine_session_updatets(session, mb);
                return 0;
            }

            return ret;
        }

        enum CAENGINE_DECRYPTERR ret = \
            caengine_session_decrypt_handshake(session, mb, nonce);

        return ret;

    } else if (nonce >= SESSION_NONCE_FIRST_TRAFFIC_PACKET) {

        enum CAENGINE_DECRYPTERR ret = caengine_message_decrypt(session, nonce, mb, session->sharedsecretkey);
        if (ret) {
            CAEDEBUG(session, "DROP: [%s] MESSAGE FAILURE",
                ((ret == CAENGINE_DECRYPTERR_REPLAY) ? "REPLAY CHECK" : "DECRYPT"));
            return ret;
        }
        caengine_session_updatets(session, mb);
        return 0;
    } else if (nonce <= SESSION_NONCE_REPEAT_HELLO) {
        CAEDEBUG(session, "nonce <= SESSION_NONCE_REPEAT_HELLO; nonce=[%d]", nonce);
        return caengine_session_decrypt_handshake(session, mb, nonce);
    } else {
        CAEDEBUG(session, "DROP: CAENGINE_DECRYPTERR_KEY_PKT_ESTABLISHED_SESSION nonce=[%d]", nonce);
        return CAENGINE_DECRYPTERR_KEY_PKT_ESTABLISHED_SESSION;
    }
    error("!!!UNREACHABLE!!!\n"); BREAKPOINT;
    return CAENGINE_DECRYPTERR_INVALID_PACKET;
}

int caengine_session_encrypt(struct caengine_session *session, struct mbuf *mb)
{

    if (!session || !mb) {
        return EINVAL;
    }

    CAEDEBUG0(session, "caengine_session_encrypt");

    caengine_session_resetiftimedout(session);

    if (session->nonce_next >= 0xfffffff0) {
        caengine_session_reset(session);
    }

    if (session->nonce_next <= CAENGINE_STATE_RECEIVED_KEY) {
        if (session->nonce_next < CAENGINE_STATE_RECEIVED_KEY) {
            caengine_session_encrypt_handshake(session, mb);
            return 0;
        } else {
            CAEDEBUG0(session, "FINAL SEND; nonce?=4");
            _calc_sharedsecret(session->sharedsecretkey
                           ,session->local_tmp_prvkey
                           ,session->remote_tmp_pubkey
                           ,NULL );
        }
    }

    caengine_message_encrypt(session, session->nonce_next, mb, session->sharedsecretkey);

    mbuf_advance(mb, -4);
    mbuf_write_u32(mb, htonl(session->nonce_next));
    mbuf_advance(mb, -4);

    session->nonce_next++;
    return 0;

}

enum CAENGINE_STATE caengine_session_state(struct caengine_session *session)
{
    if (!session) {
        return CAENGINE_STATE_INIT;
    }
    if (session->nonce_next <= CAENGINE_STATE_RECEIVED_KEY) {
        return session->nonce_next;
    }
    return (session->established) ? CAENGINE_STATE_ESTABLISHED : CAENGINE_STATE_RECEIVED_KEY;
}

static void caengine_authtoken_destructor(void *data)
{
    struct caengine_authtoken *t = data;
    list_unlink(&t->le);
    t->login = mem_deref(t->login);
    t->pword = mem_deref(t->pword);
}

static inline struct caengine_authtoken *
caengine_authtoken_get( struct caengine *caengine
                      , uint8_t chal_type
                      , uint8_t chal_lookup[7] )
{
    struct le *le;

    if (!caengine || chal_type == 0 || chal_type > 2)
        return NULL;

    struct caengine_authtoken *t;
    LIST_FOREACH(&caengine->authtokens, le) {
        t = le->data;
        if (chal_type == 1 &&
            !memcmp(chal_lookup, t->phash, 8)) {
            return t;
        } else if (chal_type == 2 &&
            !memcmp(chal_lookup, t->uhash, 8)) {
            return t;
        }
    }
    return NULL; /* unauthorized */
}

int caengine_authtoken_add( struct caengine *caengine
                          , const char *login
                          , const char *pword )
{
    int err = 0;
    struct caengine_authtoken *token;

    if (!caengine || !login || !pword)
        return EINVAL;

    token = mem_zalloc(sizeof(*token), caengine_authtoken_destructor);
    if (!token)
        return ENOMEM;

    err = str_dup(&token->login, login);
    if (err) {
        goto out;
    }

    err = str_dup(&token->pword, pword);
    if (err) {
        goto out;
    }

    /* calculate hashes */
    err = _message_hash_password(token->secret, token->uhash, login, pword, 2);
    if (err) { goto out; }
    err = _message_hash_password(token->secret, token->phash, login, pword, 1);
    if (err) { goto out; }

    /* check for dups? */

    /* now link! */
    list_append(&caengine->authtokens, &token->le, token);

out:
    if (err) {
        token = mem_deref(token);
    }
    return err;
}

static void caengine_destructor(void *data)
{
    struct caengine *c = data;
    list_flush(&c->sessions);
    list_flush(&c->authtokens);
}

int caengine_init( struct caengine **caenginep )
{
    struct caengine *c;

    if (!caenginep)
        return EINVAL;

    c = mem_zalloc(sizeof(*c), caengine_destructor);
    if (!c)
        return ENOMEM;

    list_init(&c->sessions);

#if 0
    if (NULL == private_key) {
        rand_bytes(c->my_prvkey, 32);
    } else {
        memcpy(c->my_prvkey, private_key, 32);
    }

    crypto_scalarmult_curve25519_base(c->my_pubkey, c->my_prvkey);

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
