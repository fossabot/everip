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

#if defined(HAVE_GENDO)
#include <gendo.h>
#endif

static struct everip {
    /* ritsuko */
    struct network *net;
    struct commands *commands;
    /*struct mrpinger *mrpinger;*/

    /* geofront */
    struct conduits *conduits;
    struct geofront *geofront;

    /* central dogma */
    struct caengine *caengine;
    /*struct cd_relaymap *cd_relaymap;*/
    /*struct cd_manager *cd_manager;*/
    /*struct cd_cmdcenter *cd_cmdcenter;*/

    /* terminal dogma */
    struct tmldogma *tmldogma;
    struct tunif *tunif;

    struct netevent *netevent;

    /* magi */
    /*struct magi_eventdriver *eventdriver;*/
    /*struct magi_starfinder *starfinder;*/

    /* treeoflife */
    struct treeoflife *treeoflife;

    uint16_t udp_port;

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

    /*err = mrpinger_init(&everip.mrpinger);
    if (err)
        return err;*/

    err = cmd_init(&everip.commands);
    if (err)
        return err;

    err = caengine_init(&everip.caengine);
    if (err)
        return err;

#if defined(HAVE_GENDO)
    GENDO_INIT;
#endif

    if (!everip.caengine->activated) {
        error("CAE: could not be activated...\n");
        err = EBADMSG;
        return err;
    }

    caengine_authtoken_add(everip.caengine, "EVERIP", "DEFAULT" );

    /* magi */
    /*err = magi_eventdriver_init( &everip.eventdriver, everip.caengine->my_pubkey );
    if (err)
        return err;*/

    if (!everip.udp_port)
        everip.udp_port = 1988;

    /* tree of life */
    err = treeoflife_init( &everip.treeoflife
                         , everip.caengine->my_ipv6+1 );
    if (err)
        return err;

    /* central dogma */
    /*err = cd_relaymap_init(&everip.cd_relaymap);
    if (err)
        return err;*/

    /*err = cd_manager_init(&everip.cd_manager, everip.eventdriver);
    if (err)
        return err;*/

    err = geofront_init(&everip.geofront);
    if (err)
        return err;

    /*err = cd_cmdcenter_init(&everip.cd_cmdcenter, everip.caengine->my_pubkey);
    if (err)
        return err;*/

    err = conduits_init( &everip.conduits
                       , everip.treeoflife );
    if (err)
        return err;

#if 0
    err = tmldogma_init( &everip.tmldogma
                       , NULL /*everip.eventdriver*/
                       , everip.caengine->my_ipv6);
    if (err)
        return err;
#endif

    /* do connections */

    /* connect central dogma */
    /*csock_flow(everip.cd_relaymap->router_cs, &everip.cd_manager->relaymap_cs);*/
    /*csock_flow(&everip.cd_manager->cmdcenter_cs, &everip.cd_cmdcenter->manager_cs);*/

    /* connect terminal dogma to central dogma */
    /*csock_flow( &everip.cd_manager->terminaldogma_cs
              , &everip.tmldogma->ctrdogma_cs );*/

    /* starfinder */
#if 0
    err = magi_starfinder_init( &everip.starfinder, everip.caengine->my_pubkey);
    if (err)
        return err;

    magi_eventdriver_register_star(everip.eventdriver, &everip.starfinder->eventd_cs);
#endif

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

    err = net_if_setaddr( everip.tunif->name
                        , &tmp_sa
                        , 8 );
    if (err)
        return err;
    err = net_if_setmtu( everip.tunif->name
                       , 1304);
    if (err)
        return err;

    conduits_connect_tunif(everip.conduits, &everip.tunif->tmldogma_cs);

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

#if defined(HAVE_GENDO)
    GENDO_MID;
#endif

    return 0;
}


void everip_close(void)
{

#if defined(HAVE_GENDO)
    GENDO_DEINIT;
#endif


    everip.netevent = mem_deref(everip.netevent);

    /* reverse from init */
    everip.tunif = mem_deref(everip.tunif);

    /*everip.tmldogma = mem_deref(everip.tmldogma);*/
    /*everip.cd_cmdcenter = mem_deref(everip.cd_cmdcenter);*/
    everip.conduits = mem_deref(everip.conduits);
    everip.geofront = mem_deref(everip.geofront);
    /*everip.cd_manager = mem_deref(everip.cd_manager);*/
    /*everip.cd_relaymap = mem_deref(everip.cd_relaymap);*/
    everip.caengine = mem_deref(everip.caengine);

    /*everip.eventdriver = mem_deref(everip.eventdriver);*/
    /*everip.starfinder = mem_deref(everip.starfinder);*/

    everip.commands = mem_deref(everip.commands);
    /*everip.mrpinger = mem_deref(everip.mrpinger);*/
    everip.net = mem_deref(everip.net);

    everip.treeoflife = mem_deref(everip.treeoflife);
}


struct network *everip_network(void)
{
    return everip.net;
}

struct mrpinger *everip_mrpinger(void)
{
    return NULL /*everip.mrpinger*/;
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
struct treeoflife *everip_treeoflife(void)
{
    return everip.treeoflife;
}

void everip_udpport_set(uint16_t port)
{
    everip.udp_port = port;
}
