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

#ifdef SOLARIS
#define __EXTENSIONS__ 1
#endif
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_GETOPT
#include <getopt.h>
#endif
#include <re.h>
#include <everip.h>

static void signal_handler(int sig)
{
	static bool term = false;

	if (term) {
		mod_close();
		exit(0);
	}

	term = true;

	info("terminated by signal %d\n", sig);

	module_app_unload();
	re_cancel();
}

static int cmd_quit(struct re_printf *pf, void *unused)
{
	int err;

	(void)unused;
	err = re_hprintf(pf, "Good-bye.\n");
	module_app_unload();
	re_cancel();
	return err;
}

static const struct cmd cmdv[] = {
	{"quit", 'q', 0, "Quit", cmd_quit},
};

int main(int argc, char *argv[])
{
	int err;
	(void)re_fprintf( stderr
					, "\nStarting connectFree(R) EVER/IP(R) for %s/%s [%s]\n"
					  "Copyright 2016-2017 Kristopher Tate and connectFree Corporation.\n"
					  "All Rights Reserved. Protected by International Patent Treaties.\n"
					  "More information: select \"Legal Information\" from the main menu.\n\n"
					, sys_os_get(), sys_arch_get()
					, EVERIP_VERSION);

#if !defined(WIN32) && !defined(CYGWIN)
	if(getuid() != 0 || geteuid() != 0) {
	  error( "EVER/IP(R) requires you to be a super user on %s/%s.\n"
	  	   , sys_os_get(), sys_arch_get());
	  info("Hint: Please run `everip` again as a super user to continue.\n");
	  return EINVAL;
	}
#endif

	(void)sys_coredump_set(false);

	err = libre_init();
	if (err)
		goto out;

	err = everip_init();
	if (err) {
		warning("main: core init failed (%m)\n", err);
		goto out;
	}

	err = cmd_register(everip_commands(), cmdv, ARRAY_SIZE(cmdv));
	if (err)
		goto out;

	info("EVER/IP(R) is READY.\n\n");

	err = re_main(signal_handler);

 out:
	cmd_unregister(everip_commands(), cmdv);
	everip_close();
	debug("main: unloading modules..\n");
	mod_close();
	libre_close();

	/* Check for memory leaks */
	tmr_debug();
	mem_debug();
	return err;
}
