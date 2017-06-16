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
};

static struct csock *eth_handle_incoming( struct csock *csock
										, struct mbuf *mb )
{
	/*struct eth_csock *eth_c = (struct eth_csock *)csock;*/

	(void)csock;
	(void)mb;

	return NULL;
}


static void eth_c_destructor(void *data)
{
	struct eth_csock *eth_c = data;
	csock_stop(&eth_c->csock);
}

static struct eth_csock *eth_c = NULL;

static int module_init(void)
{
	int err = 0;

	eth_c = mem_zalloc(sizeof(*eth_c), eth_c_destructor);
	if (!eth_c)
		return ENOMEM;


	eth_c->csock.send = eth_handle_incoming;

	conduits_register( everip_conduits()
					 , "ETH"
					 , "Layer Two (Ethernet) Driver Conduit"
					 , (struct csock *)eth_c
					 );

/*out:*/
	if (err) {
		mem_deref(eth_c);
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
