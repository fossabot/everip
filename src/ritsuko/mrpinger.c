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

static bool _clk_hashid_ah(struct le *le, void *arg)
{
    struct mrpinger_clock *clk = le->data;
    uint32_t hashid = *(uint32_t *)arg;
    /*re_printf("DELETEME searching for hashid=%u\n", hashid);*/
    return (clk->hashid == hashid);
}

static void _clock_timeout(void *data)
{
	struct mrpinger_clock *clk = data;
	if (!clk->time_sent) {
		clk->time_sent = (uint32_t)((long long)(tmr_jiffies())/1000);
		/* do call back */
		clk->cb_ping(clk->hashid, clk->cookie, clk->userdata);
		tmr_start(&clk->tmr, clk->time_delay, _clock_timeout, clk);
	} else {
		list_unlink(&clk->le);
		clk = mem_deref(clk);
	}
}

static void _mrpinger_clock_destructor(void *data)
{
	struct mrpinger_clock *clk = data;
	list_unlink(&clk->le);

	/* sorry, we failed! */
	if (clk->cb_pong)
		clk->cb_pong(NULL, 0, 0, clk->userdata);

	tmr_cancel(&clk->tmr);
}

int mrpinger_ping( struct mrpinger *pinger
				 , uint64_t delay
				 , mrpinger_pong_h *cb_pong
				 , mrpinger_ping_h *cb_ping
				 , void *userdata )
{
	int err = 0;
	struct mrpinger_clock *clk;

	if (!pinger || !delay || !cb_pong || !cb_ping)
		return EINVAL;

	clk = mem_zalloc(sizeof(*clk), _mrpinger_clock_destructor);
	if (!clk)
		return ENOMEM;

	clk->cookie = rand_u64();

	do {
		clk->hashid = rand_u32(); /* search for unique id */
	} while (hash_lookup(pinger->clocks, clk->hashid, _clk_hashid_ah, &clk->hashid));

	clk->userdata = userdata;
	clk->cb_pong = cb_pong;
	clk->cb_ping = cb_ping;
	clk->time_delay = delay;

	hash_append( pinger->clocks
			   , clk->hashid
			   , &clk->le
			   , clk );

	tmr_init(&clk->tmr);
	tmr_start(&clk->tmr, 0, _clock_timeout, clk);

	return err;
}

int mrpinger_pong( struct mrpinger *pinger
				 , uint32_t version
				 , struct pl *_pl )
{
	if (!pinger || !_pl)
		return EINVAL;

	if (_pl->l < 12)
		return EINVAL;

	uint32_t hashid = pl_read_u32(_pl);

	struct le *result = hash_lookup( pinger->clocks
								   , hashid
								   , _clk_hashid_ah
								   , &hashid);
	if (!result) {
		return EINVAL;
	}

	struct mrpinger_clock *clk = result->data;

	uint64_t cookie = pl_read_u64(_pl);

	if (clk->cookie != cookie) {
		debug("mrpinger_pong: invalid cookie;\n");
		return EINVAL;
	}

	uint64_t ttl = (uint32_t)((long long)(tmr_jiffies())/1000) - clk->time_sent;

	clk->cb_pong(_pl, version, ttl, clk->userdata);
	clk->cb_pong = NULL;

	clk = mem_deref(clk);
	return EINVAL;
}

static void _mrpinger_destructor(void *data)
{
	struct mrpinger *p = data;
	hash_flush(p->clocks);
	p->clocks = mem_deref( p->clocks );
}

int mrpinger_init( struct mrpinger **mrpingerp )
{
	struct mrpinger *p;

	if (!mrpingerp)
		return EINVAL;

	p = mem_zalloc(sizeof(*p), _mrpinger_destructor);
	if (!p)
		return ENOMEM;

	hash_alloc(&p->clocks, 4);

	*mrpingerp = p;

	return 0;
}
