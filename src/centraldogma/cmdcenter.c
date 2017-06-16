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

/* from the central dogma manager */
static struct csock *_from_manager( struct csock *csock
							      , struct mbuf *mb )
{
	if (!csock || !mb)
		return NULL;

	struct cd_cmdcenter *cc = container_of( csock
		                                  , struct cd_cmdcenter
		                                  , manager_cs);

	/*re_printf("_from_manager\n");*/

	struct sess_wireheader sess_wh;
	mbuf_read_mem(mb, (uint8_t *)&sess_wh, SESS_WIREHEADER_LENGTH);

	uint64_t label = arch_betoh64(sess_wh.sh.label_be);

	/*re_printf("label = %w\n", &label, 4);*/

    if (mbuf_get_left(mb) < 4 + CTRL_HEADER_LENGTH) {
        /*info("DROP\n");*/
        return NULL;
    }

    ASSERT_TRUE(sess_wh.flags & SESS_WIREHEADER_flags_CTRLMSG);

    if (chksum_buf(mbuf_buf(mb), mbuf_get_left(mb))) {
        info("DROP invalid checksum \n");
        return NULL;
    }

    size_t ctrlhead_pos = mb->pos;

    /*re_printf("now, do ctrl logic!\n");*/

    uint16_t checksum_be = mbuf_read_u16(mb); (void)checksum_be;
    uint16_t type_be = mbuf_read_u16(mb);

    /*BREAKPOINT;*/

    if (type_be == CTRL_TYPE_ERROR_be) {
    	error("got error!\n");
        return NULL; /*handleError(msg, ch, label, labelStr);*/

    } else if (type_be == CTRL_TYPE_PINGKEY_be
            || type_be == CTRL_TYPE_PING_be)
    {


        /* grab magic and version */
        uint32_t magic = mbuf_read_u32(mb);
        uint32_t version = arch_betoh32(mbuf_read_u32(mb));

        if (!everip_version_compat(EVERIP_VERSION_PROTOCOL, version)) {
            debug("DROP ping from incompatible version\n");
            return NULL;
        }

        if (type_be == CTRL_TYPE_PINGKEY_be) {
/*            if (mbuf_get_left(mb) < Control_KeyPing_HEADER_SIZE) {
                debug("DROP RUNT\n");
                return NULL;
            }
*/
            if (magic != arch_htobe32(0x09f91102)) {
                debug("DROP bad magic\n");
                return NULL;
            }

            mbuf_set_pos(mb, ctrlhead_pos);
            mbuf_advance(mb, 2); /* skip checksum */
            mbuf_write_u16(mb, CTRL_TYPE_PONGKEY_be); /* write new type */
            mbuf_write_u32(mb, arch_htobe32(0x89abcdef)); /* write new magic */
            mbuf_write_u32(mb, arch_htobe32(EVERIP_VERSION_PROTOCOL)); /* write version */
            mbuf_write_mem(mb, cc->local_pubkey, 32); /* write-out key */

        } else if (type_be == CTRL_TYPE_PING_be) {
            if (magic != arch_htobe32(0x09f91102)) {
                debug("DROP bad magic\n");
                return NULL;
            }

            mbuf_set_pos(mb, ctrlhead_pos);
            mbuf_advance(mb, 2); /* skip checksum */
            mbuf_write_u16(mb, CTRL_TYPE_PONG_be); /* write new type */
            mbuf_write_u32(mb, arch_htobe32(0x9d74e35b)); /* write new magic */
            mbuf_write_u32(mb, arch_htobe32(EVERIP_VERSION_PROTOCOL)); /* write version */
        } else {
            ASSERT_TRUE(0);
        }

        /*mbuf_set_end(mb, mb->pos);*/ /* lock-down packet */
        mbuf_set_pos(mb, ctrlhead_pos);
        /*debug("CMD LENGTH == [%u]\n", mb->end - mb->pos);*/
        mbuf_write_u16(mb, 0); /* reset for checksum */
        mbuf_set_pos(mb, ctrlhead_pos);
        mbuf_write_u16(mb, chksum_buf(mbuf_buf(mb), mbuf_get_left(mb)) );
        mbuf_set_pos(mb, ctrlhead_pos);

        /* slap-on a routeheader!! */
        mbuf_advance(mb, -(SESS_WIREHEADER_LENGTH));
        struct sess_wireheader *out_sess_wh = (struct sess_wireheader *)mbuf_buf(mb);
        memset(out_sess_wh, 0, SESS_WIREHEADER_LENGTH);

        _wireheader_setversion(&out_sess_wh->sh, 1); /* current version is 1 */
        out_sess_wh->sh.label_be = arch_htobe64(label);
        out_sess_wh->flags |= SESS_WIREHEADER_flags_CTRLMSG;

        /* the end of this message should have a pinger id? */

        return csock_next(&cc->manager_cs, mb);

    } else if (type_be == CTRL_TYPE_PONGKEY_be
            || type_be == CTRL_TYPE_PONG_be)
    {
    	error("got pong!\n");

        /*BREAKPOINT;*/

        if (mbuf_get_left(mb) < 8)
            return NULL;

        /* grab magic and version */
        uint32_t magic = mbuf_read_u32(mb);
        uint32_t version = arch_betoh32(mbuf_read_u32(mb));

        if (!everip_version_compat(EVERIP_VERSION_PROTOCOL, version)) {
            debug("DROP ping from incompatible version[%u]\n", version);
            return NULL;
        }

        if (type_be == CTRL_TYPE_PONG_be) {
            if (magic != arch_htobe32(0x9d74e35b)) {
                return NULL;
            }
        } else if (type_be == CTRL_TYPE_PONG_be) {
            if (magic != arch_htobe32(0x89abcdef)) {
                return NULL;
            }
        }

        struct pl _data;
        pl_set_mbuf(&_data, mb);
        mrpinger_pong( everip_mrpinger()
                     , version
                     , &_data);
        return NULL;
    }

    info( "DROP control packet of unknown type [%d]"
    	, arch_betoh16(type_be));

    return NULL;
}

/* from the central dogma (rmap) pinger */
static struct csock *_from_relaymap( struct csock *csock
							       , struct mbuf *mb )
{
	if (!csock || !mb)
		return NULL;

	return NULL;
}

static void cd_cmdcenter_destructor(void *data)
{
	struct cd_cmdcenter *cc = data;
	(void)cc;
}

struct csock *cd_cmdcenter_sendcmd( struct cd_cmdcenter *cc, struct mbuf *mb )
{
    if (!cc || !mb)
        return NULL;

    debug("cd_cmdcenter_sendcmd\n");

    return csock_next(&cc->manager_cs, mb);
}

int cd_cmdcenter_init( struct cd_cmdcenter **cmdcenterp
                     , const uint8_t local_pubkey[32])
{
	struct cd_cmdcenter *cc;

	if (!cmdcenterp)
		return EINVAL;

	cc = mem_zalloc(sizeof(*cc), cd_cmdcenter_destructor);
	if (!cc)
		return ENOMEM;

    memcpy(cc->local_pubkey, local_pubkey, 32);

    cc->manager_cs.send = _from_manager;
    cc->rpinger_cs.send = _from_relaymap;

	*cmdcenterp = cc;

	return 0;
}
