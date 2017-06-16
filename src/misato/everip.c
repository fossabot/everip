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

#include <sodium.h>

static struct everip {
	/* ritsuko */
	struct network *net;
	struct commands *commands;
	struct mrpinger *mrpinger;

	/* geofront */
	struct conduits *conduits;
	struct geofront *geofront;

	/* central dogma */
	struct caengine *caengine;
	struct cd_relaymap *cd_relaymap;
	struct cd_manager *cd_manager;
	struct cd_cmdcenter *cd_cmdcenter;

	/* terminal dogma */
	struct tmldogma *tmldogma;
	struct tunif *tunif;

	/* magi */
	struct magi_eventdriver *eventdriver;
	struct magi_starfinder *starfinder;

	struct netevent *netevent;

	struct licenser *_licenser;

} everip;


int everip_init(void)
{
	int err;

	memset(&everip, 0, sizeof(struct everip));

    if (sodium_init() == -1) {
        return EINVAL;
    }

	/* Initialise Network */
	err = net_alloc(&everip.net);
	if (err) {
		return err;
	}

	err = mrpinger_init(&everip.mrpinger);
	if (err)
		return err;

	err = cmd_init(&everip.commands);
	if (err)
		return err;

	/* initiate licenser */
	err = licenser_alloc(&everip._licenser, "ever.license");
	if (err) {
		error("A valid license file was unable to be loaded;\n"
			  "Please contact your nearest EVER/IP(R) distributor,\n"
			  "or please visit http://connectfree.jp/ for more information.\n");
		return err;
	}

	err = licenser_authenticate( everip._licenser );
	if (err)
		return err;

	uint8_t license_key_private[32];
	uint8_t license_key_public[32];
	err = licenser_keyprivate_get(everip._licenser, license_key_private);
	if (err)
		return err;

	err = caengine_init(&everip.caengine, license_key_private);
	if (err)
		return err;

	struct pl pubkey_pl = {
		 .p = licenser_keypublic_get(everip._licenser)
		,.l = 0
	};
	pubkey_pl.l = strlen(pubkey_pl.p);

	err = caengine_keys_parse(&pubkey_pl, license_key_public);
	if (err)
		return err;

	/* check if license_key_public matches calculated value */
	if (memcmp(everip.caengine->my_pubkey, license_key_public, 32)) {
		error("Invalid license file was loaded...\n");
		return EINVAL;
	}

	/* magi */
	err = magi_eventdriver_init( &everip.eventdriver, everip.caengine->my_pubkey );
	if (err)
		return err;

	/* central dogma */
	err = cd_relaymap_init(&everip.cd_relaymap);
	if (err)
		return err;

	err = cd_manager_init(&everip.cd_manager, everip.eventdriver);
	if (err)
		return err;

	err = geofront_init(&everip.geofront);
	if (err)
		return err;

	err = cd_cmdcenter_init(&everip.cd_cmdcenter, everip.caengine->my_pubkey);
	if (err)
		return err;

	err = conduits_init( &everip.conduits
		               , everip.cd_relaymap
		               , everip.cd_cmdcenter
		               , everip.eventdriver );
	if (err)
		return err;

	err = tmldogma_init( &everip.tmldogma
					   , everip.eventdriver
					   , everip.caengine->my_ipv6);
	if (err)
		return err;

	/* do connections */

	/* connect central dogma */
	csock_flow(everip.cd_relaymap->router_cs, &everip.cd_manager->relaymap_cs);
	csock_flow(&everip.cd_manager->cmdcenter_cs, &everip.cd_cmdcenter->manager_cs);

	/* connect terminal dogma to central dogma */
	csock_flow( &everip.cd_manager->terminaldogma_cs
		      , &everip.tmldogma->ctrdogma_cs );

	/* starfinder */
	err = magi_starfinder_init( &everip.starfinder, everip.caengine->my_pubkey);
	if (err)
		return err;

	magi_eventdriver_register_star(everip.eventdriver, &everip.starfinder->eventd_cs);

	/*net_change(everip.net, 2, NULL, NULL);*/
	err = netevent_init( &everip.netevent );
	if (err)
		return err;

	struct sa tmp_sa;
	sa_init(&tmp_sa, AF_INET6);
	sa_set_in6(&tmp_sa, everip.caengine->my_ipv6, 0);

	info("UNLOCKING LICENSED EVER/IP(R) ADDRESS\n%j\n", &tmp_sa, 16);

#if 1
#if !defined(WIN32) && !defined(CYGWIN)
	err = tunif_init( &everip.tunif );
	if (err)
		return err;

#if 1
	err = net_if_setaddr( everip.tunif->name
		                , &tmp_sa
		                , 8 );
	if (err)
		return err;
	err = net_if_setmtu( everip.tunif->name
		               , 1304);
	if (err)
		return err;
#endif
	csock_flow( &everip.tunif->tmldogma_cs
			  , &everip.tmldogma->tunadapt_cs);

#endif
#endif

#if !defined(WIN32) && !defined(CYGWIN)
	module_preload("stdio");
#else
	module_preload("wincon");
#endif
	module_preload("dcmd");

	/* conduits*/
	module_preload("udp");
	module_preload("eth");


	everip._licenser = mem_deref(everip._licenser);

	return 0;
}


void everip_close(void)
{

	everip._licenser = mem_deref(everip._licenser);

	everip.netevent = mem_deref(everip.netevent);

	/* reverse from init */
	everip.tunif = mem_deref(everip.tunif);

	everip.tmldogma = mem_deref(everip.tmldogma);
	everip.cd_cmdcenter = mem_deref(everip.cd_cmdcenter);
	everip.conduits = mem_deref(everip.conduits);
	everip.geofront = mem_deref(everip.geofront);
	everip.cd_manager = mem_deref(everip.cd_manager);
	everip.cd_relaymap = mem_deref(everip.cd_relaymap);
	everip.caengine = mem_deref(everip.caengine);

	everip.eventdriver = mem_deref(everip.eventdriver);
	everip.starfinder = mem_deref(everip.starfinder);

	everip.commands = mem_deref(everip.commands);
	everip.mrpinger = mem_deref(everip.mrpinger);
	everip.net = mem_deref(everip.net);
}


struct network *everip_network(void)
{
	return everip.net;
}

struct mrpinger *everip_mrpinger(void)
{
	return everip.mrpinger;
}

struct commands *everip_commands(void)
{
	return everip.commands;
}

struct caengine *everip_caengine(void)
{
	return everip.caengine;
}

struct conduits *everip_conduits(void)
{
	return everip.conduits;
}
