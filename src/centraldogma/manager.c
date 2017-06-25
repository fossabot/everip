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

/*static struct csock *__do_ctrl( struct cd_manager *manager
							  , struct mbuf *mb )
{
	if (!manager || !mb)
		return NULL;

	//re_printf("X:S %w\n", mbuf_buf(mb), mb->size);

	struct mbuf_ext *mbe = (struct mbuf_ext *)mb->buf;
	mbuf_set_pos(mb, mbe->h);

}*/

struct cd_manager_sess {
    struct caengine_session *caes;
    struct {
	    int64_t lastin;
	    int64_t lastout;
	    int64_t lastsearch;
    } time;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint32_t hndl_recv;
    uint32_t hndl_send;
    uint32_t version;
    uint64_t label_recv;
    uint64_t label_send;

    uint8_t ip6[16];

    struct cd_manager *ctx;
    struct le le;
};

static struct csock *_from_eventd( struct csock *csock
								 , struct mbuf *mb )
{
	struct cd_manager *manager = container_of(csock, struct cd_manager, eventd_cs);

    debug("_from_eventd ->[via td]->_from_terminaldogma\n");

    /* only EVD_STAR_SENDMSG should be redirecting... */
    ASSERT_TRUE( EVD_STAR_SENDMSG == mbuf_read_u32(mb) );
    mbuf_advance(mb, 4); /* required? */

    /* redirect... not so happy about this... */
    CSOCK_CALL( manager->terminaldogma_cs.send
    		  , &manager->terminaldogma_cs
    		  , mb);

    return NULL;
}

static bool _session_ipv6_cb(struct le *le, void *arg)
{
    struct cd_manager_sess *s = le->data;
    uint8_t *ip6 = arg;
    /*if (!s->caes) return false;*/
    return 0 == memcmp(&s->ip6, ip6, 16);
}

static bool _session_noh_cb(struct le *le, void *arg)
{
    struct cd_manager_sess *s = le->data;
    return s->hndl_recv == *(uint32_t *)arg;
}

static struct cd_manager_sess *_session_fromhandle( struct cd_manager *manager
												  , uint32_t noh)
{
    struct cd_manager_sess *sess;
    if (!manager)
        return NULL;

    sess = list_ledata(hash_lookup( manager->sessions
                                  , noh
                                  , _session_noh_cb
                                  , &noh));

	return sess;
}

static void cd_manager_sess_destructor(void *data)
{
	struct cd_manager_sess *s = data;
	s->caes = mem_deref(s->caes);
	list_unlink(&s->le);

}

static struct cd_manager_sess *_session_get( struct cd_manager *manager
										   , uint8_t ip6[16]
                                           , uint8_t pubkey[32]
                                           , uint32_t version
                                           , uint64_t label )
{
	/* first, check to see if we have a session via ipv6 */
	int err = 0;
	struct cd_manager_sess *sess = NULL;

	if (!manager || !ip6 || !pubkey)
		return NULL;

    uint32_t hashid = hash_joaat(ip6, 16);

	debug("HASHID[%w] == %u\n", ip6, 16, hashid);
    sess = list_ledata(hash_lookup( manager->sessions
    							  , hashid
    							  , _session_ipv6_cb
    							  , ip6));

    if (sess) {
        sess->version = (sess->version) ? sess->version : version;
        sess->label_send = (sess->label_send) ? sess->label_send : label;
        return sess;
    }

	sess = mem_zalloc(sizeof(*sess), cd_manager_sess_destructor);
	if (!sess)
		return NULL;

	/* create cae_session */
	err = caengine_session_new( &sess->caes
							  , everip_caengine()
							  , pubkey
							  , false);
	if (err) {
		error("caengine_session_new %m", err);
		sess = mem_deref(sess);
		return NULL;
	}

    caengine_session_setdbg(sess->caes, "sky");

	sess->ctx = manager;
    sess->version = version;
    sess->label_send = label;
    sess->hndl_recv = hashid;
    sess->time.lastout = (uint32_t)((long long)(tmr_jiffies())/1000);
    sess->time.lastin = sess->time.lastout;

    memcpy(sess->ip6, ip6, 16);

	hash_append( manager->sessions
			   , hashid
			   , &sess->le
			   , sess
			   );

	return sess;
}
static struct csock *_from_relaymap( struct csock *csock
							       , struct mbuf *mb )
{
	if (!csock || !mb)
		return NULL;
	struct cd_manager *manager = container_of(csock, struct cd_manager, relaymap_cs);

	/*re_printf("_from_relaymap\n");*/

	size_t pfix = mb->pos;

	if (mbuf_get_left(mb) < RELAYMAP_HEADER_LENGTH + 4)
		return NULL;

	struct rmap_wireheader *wheader = (struct rmap_wireheader *)mbuf_buf(mb);
	wheader->label_be = reverse_b64(wheader->label_be);
	mbuf_advance(mb, RELAYMAP_HEADER_LENGTH);
    uint32_t noh = arch_betoh32(mbuf_read_u32(mb));

    if (noh == 0xffffffff) {
    	{
		    struct sess_wireheader sess_wh;
		    memset(&sess_wh, 0, SESS_WIREHEADER_LENGTH);
			mbuf_set_pos(mb, pfix);
		    mbuf_read_mem(mb, (uint8_t *)&sess_wh.sh, RELAYMAP_HEADER_LENGTH);
		    mbuf_advance(mb, 4);

		    mbuf_advance(mb, -(SESS_WIREHEADER_LENGTH));

			sess_wh.flags = SESS_WIREHEADER_flags_INCOMING | SESS_WIREHEADER_flags_CTRLMSG;
		    mbuf_write_mem(mb, (uint8_t *)&sess_wh, SESS_WIREHEADER_LENGTH);
		    mbuf_advance(mb, -(SESS_WIREHEADER_LENGTH));

		    //re_printf("X:E %w\n", mbuf_buf(mb), mb->size);

		    return csock_next(&manager->cmdcenter_cs, mb);
    	}
    }

    mbuf_advance(mb, -4);

    uint8_t first_sixteen[16];
    size_t length0 = mbuf_get_left(mb);
    ASSERT_TRUE(length0 >= 16);
    memcpy(first_sixteen, mbuf_buf(mb), 16);

    if (length0 < 4 + 20) {
        debug("DROP runt\n");
        return NULL;
    }

    struct cd_manager_sess *session = NULL;

    if (noh > 3) {
		session = _session_fromhandle(manager, noh);
		if (!session) {
			debug("DROP handle was invalid\n");
			return NULL;
		}
        mbuf_advance(mb, 4);
    } else {
        if (mbuf_get_left(mb) < CAE_HEADER_LENGTH + 4) {
            debug("DROP runt\n");
            return NULL;
        }
        debug("Hello, I would like to make a session with you!\n");

        struct cae_header *cae_h = (struct cae_header *)mbuf_buf(mb);
        uint8_t ip6[16];

        if (!addr_calc_pubkeyaddr(ip6, cae_h->d )) {
            debug("DROP non valid key\n");
            return NULL;
        }

        if (!memcmp(cae_h->d, everip_caengine()->my_pubkey, 32)) {
            debug("DROP cannot connect to ourselves\n");
            return NULL;
        }

        uint64_t label = arch_betoh64(wheader->label_be);

        debug("label = %w\n", &label, 4);

        session = _session_get(manager, ip6, cae_h->d, 0, label);
        caengine_session_resetiftimedout( session->caes );
    }

    if (!session) {
    	debug("something went wrong;\n");
    	return NULL;
    }

    bool _setup = (noh <= 3);

    /* try to decrypt */
	if (caengine_session_decrypt(session->caes, mb)) {
		warning("decryption failed!!\n");
		/* TODO, send failure packet */
		return NULL;
	} else {
		debug("decryption OK!!\n");
	}

    session->time.lastin = (uint32_t)((long long)(tmr_jiffies())/1000);
    session->bytes_in += mbuf_get_left(mb);

    if (_setup) {
        session->hndl_send = arch_betoh32(mbuf_read_u32(mb));
        info("session->hndl_send = %u\n", session->hndl_send);
    }

    mbuf_advance(mb, -SESS_WIREHEADER_LENGTH);

    struct sess_wireheader *header = (struct sess_wireheader *)mbuf_buf(mb);

    if (_setup) {
        memcpy(&header->sh, wheader, RELAYMAP_HEADER_LENGTH);
    } else {
        ASSERT_TRUE(&header->sh == wheader);
    }

    header->version_be = arch_htobe32(session->version);
    memcpy(header->ip6, session->caes->remote_ip6, 16);
    memcpy(header->pubkey, session->caes->remote_pubkey, 32);

    /*header->unused = 0; ??? */
    header->flags = SESS_WIREHEADER_flags_INCOMING;

    uint64_t path = arch_betoh64(wheader->label_be);
    if (!session->label_send) {
        session->label_send = path;
    }
    if (path != session->label_recv) {
        session->label_recv = path;
    }

    /* cleared for terminal dogma */
    return csock_next(&manager->terminaldogma_cs, mb);
}

static struct csock *_clear_to_send( struct cd_manager *manager
							       , struct cd_manager_sess *session
							       , struct mbuf *mb )
{
	if (!manager || !session || !mb)
		return NULL;

	struct sess_wireheader *hdr = (struct sess_wireheader *)mbuf_buf(mb);
	struct rmap_wireheader *sh;

	mbuf_advance(mb, SESS_WIREHEADER_LENGTH);
	caengine_session_resetiftimedout( session->caes );
	if (caengine_session_state(session->caes) < CAENGINE_STATE_RECEIVED_KEY) {
		mbuf_advance(mb, -4);
        info("writing session->hndl_recv = %u\n", session->hndl_recv);
		mbuf_write_u32(mb, arch_htobe32(session->hndl_recv));
		mbuf_advance(mb, -4);

		mbuf_advance(mb, -(RELAYMAP_HEADER_LENGTH + CAE_HEADER_LENGTH));
		memcpy(mbuf_buf(mb), &hdr->sh, RELAYMAP_HEADER_LENGTH);
		sh = (struct rmap_wireheader *)mbuf_buf(mb);
		mbuf_advance(mb, (RELAYMAP_HEADER_LENGTH + CAE_HEADER_LENGTH));
	} else {
		sh = &hdr->sh;
	}

	session->time.lastout = (uint32_t)((long long)(tmr_jiffies())/1000);
	session->bytes_out += mbuf_get_left(mb);

	ASSERT_TRUE(!caengine_session_encrypt(session->caes, mb));

	if (caengine_session_state(session->caes) >= CAENGINE_STATE_RECEIVED_KEY) {
		mbuf_advance(mb, -4);
        /*info("writing session->hndl_send = %u\n", session->hndl_send);*/
		mbuf_write_u32(mb, arch_htobe32(session->hndl_send));
		mbuf_advance(mb, -4);
	}

	mbuf_advance(mb, -RELAYMAP_HEADER_LENGTH);
    /*info("HOW CLOSE? %d\n", (uintptr_t)mbuf_buf(mb) - (uintptr_t)sh);*/
	ASSERT_TRUE((uint8_t*)sh == mbuf_buf(mb));

    if (!sh->label_be) {
        memset(sh, 0, RELAYMAP_HEADER_LENGTH);
        sh->label_be = arch_htobe64(session->label_send);
        _wireheader_setversion(sh, 1);
    }

	return csock_next(&manager->relaymap_cs, mb);
}

static struct csock *_from_terminaldogma( struct csock *csock
							       		, struct mbuf *mb )
{
	struct cd_manager_sess *session = NULL;
	struct cd_manager *manager = container_of( csock
		       								 , struct cd_manager
		       								 , terminaldogma_cs);

	(void)manager;
	debug("_from_terminaldogma\n");


    ASSERT_TRUE(mbuf_get_left(mb) >= SESS_WIREHEADER_LENGTH + WIRE_DATA_LENGTH);

	struct sess_wireheader *hdr = (struct sess_wireheader *)mbuf_buf(mb);
	struct wire_data *wdata = (struct wire_data *)(void *)&hdr[1];

	/* get session */
    uint32_t hashid = hash_joaat(hdr->ip6, 16);
    debug("HASHID[%w] == %u\n", hdr->ip6, 16, hashid);
    session = list_ledata(hash_lookup( manager->sessions
    							  , hashid
    							  , _session_ipv6_cb
    							  , hdr->ip6));
    if (!session) {
    	if (!is_allzero(hdr->pubkey, 32) && hdr->version_be) {
    		session = _session_get( manager
    							  , hdr->ip6
    							  , hdr->pubkey
    							  , arch_betoh32(hdr->version_be)
    							  , arch_betoh64(hdr->sh.label_be));
    	} else {
    		error("Searching for node...\n");
    		return NULL;
    	}
    }

    if (hdr->version_be) {
    	session->version = arch_betoh32(hdr->version_be);
    }

    if (!session->version) {
        /*BREAKPOINT;*/
        error("Searching for node...\n");
        return NULL;
    }

    if (hdr->sh.label_be) {
        // fallthrough
    } else if (session->label_send) {
        memset(&hdr->sh, 0, RELAYMAP_HEADER_LENGTH);
        hdr->sh.label_be = arch_htobe64(session->label_send);
        _wireheader_setversion(&hdr->sh, 1);
    } else {
        /*BREAKPOINT;*/
        error("Searching for node...\n");
        return NULL;
    }

    /* limit to magi messages, UNLESS we have a pvsession */
    caengine_session_resetiftimedout( session->caes );
#if 0
    if ( wire_data__ctype_get(wdata) != EIPCTYPES_MAGI
      && caengine_session_state(session->caes) < CAENGINE_STATE_RECEIVED_KEY )
    {
        /*error("X:TODO lookup\n");*/
        return NULL;
    }
#endif

	return _clear_to_send(manager, session, mb);
}

static struct csock *_from_cmdcenter( struct csock *csock
							       , struct mbuf *mb )
{
	struct cd_manager *manager = container_of( csock
		       								 , struct cd_manager
		       								 , cmdcenter_cs);

	debug("_from_cmdcenter\n");

    ASSERT_TRUE(mbuf_get_left(mb) >= SESS_WIREHEADER_LENGTH);

    struct sess_wireheader *header = (struct sess_wireheader *)mbuf_buf(mb);
    if (header->flags & SESS_WIREHEADER_flags_CTRLMSG) {
	    if (!is_allzero(header->pubkey, 32) || !is_allzero(header->ip6, 16)) {
	        debug("DROP found destination key or IP");
	        return NULL;
	    }
	    struct rmap_wireheader rh;
	    memcpy(&rh, &header->sh, RELAYMAP_HEADER_LENGTH);

	    mbuf_advance(mb, SESS_WIREHEADER_LENGTH);
	    mbuf_advance(mb, -(RELAYMAP_HEADER_LENGTH + 4));
	    mbuf_write_mem(mb, (uint8_t *)&rh, RELAYMAP_HEADER_LENGTH);
	    mbuf_write_u32(mb, 0xffffffff);
	    mbuf_advance(mb, -(RELAYMAP_HEADER_LENGTH + 4));

	    return csock_next(&manager->relaymap_cs, mb);
    }

    BREAKPOINT;

	return NULL;
}

static void cd_manager_destructor(void *data)
{
	struct cd_manager *m = data;
	csock_stop(&m->relaymap_cs);
	csock_stop(&m->cmdcenter_cs);
	csock_stop(&m->terminaldogma_cs);

	hash_flush(m->sessions);
	m->sessions = mem_deref(m->sessions);

}

int cd_manager_init( struct cd_manager **managerp
				   , struct magi_eventdriver *eventd )
{
	struct cd_manager *m;

	if (!managerp)
		return EINVAL;

	m = mem_zalloc(sizeof(*m), cd_manager_destructor);
	if (!m)
		return ENOMEM;

	m->relaymap_cs.send = _from_relaymap;
	m->cmdcenter_cs.send = _from_cmdcenter;
	m->terminaldogma_cs.send = _from_terminaldogma;

	hash_alloc(&m->sessions, 128);

	/* hook into events */
	m->eventd_cs.send = _from_eventd;
	magi_eventdriver_register_core( eventd
								  , &m->eventd_cs
								  , EVD_STAR_SENDMSG );

	*managerp = m;

	return 0;
}


