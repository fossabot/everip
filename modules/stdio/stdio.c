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
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

enum {
	RELEASE_VAL = 250  /**< Key release value in [ms] */
};

struct ui_st {
	struct tmr tmr;
	struct termios term;
	bool term_set;
};

static struct ui_st *ui_state;

static void ui_destructor(void *arg)
{
	struct ui_st *st = arg;

	fd_close(STDIN_FILENO);

	if (st->term_set)
		tcsetattr(STDIN_FILENO, TCSANOW, &st->term);

	tmr_cancel(&st->tmr);
}


static int print_handler(const char *p, size_t size, void *arg)
{
	(void)arg;
	return 1 == fwrite(p, size, 1, stderr) ? 0 : ENOMEM;
}


static void report_key(struct ui_st *ui, char key)
{
	static struct re_printf pf_stderr = {print_handler, NULL};
	(void)ui;

	ui_input_key(key, &pf_stderr);
}


static void timeout(void *arg)
{
	struct ui_st *st = arg;

	/* Emulate key-release */
	report_key(st, KEYCODE_REL);
}


static void ui_fd_handler(int flags, void *arg)
{
	struct ui_st *st = arg;
	char key;
	(void)flags;

	if (1 != read(STDIN_FILENO, &key, 1)) {
		return;
	}

	tmr_start(&st->tmr, RELEASE_VAL, timeout, st);
	report_key(st, key);
}


static int term_setup(struct ui_st *st)
{
	struct termios now;
	if (tcgetattr(STDIN_FILENO, &st->term) < 0)
		return errno;

	now = st->term;

	now.c_lflag |= ISIG;
	now.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
	now.c_cc[VMIN] = 1;
	now.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &now) < 0)
		return errno;
	st->term_set = true;
	return 0;
}


static int ui_alloc(struct ui_st **stp)
{
	struct ui_st *st;
	int err;

	if (!stp)
		return EINVAL;

	st = mem_zalloc(sizeof(*st), ui_destructor);
	if (!st)
		return ENOMEM;

	tmr_init(&st->tmr);

	err = fd_listen(STDIN_FILENO, FD_READ, ui_fd_handler, st);
	if (err)
		goto out;

	err = term_setup(st);
	if (err) {
		info("stdio: could not setup terminal: %m\n", err);
		err = 0;
	}

 out:
	if (err)
		mem_deref(st);
	else
		*stp = st;

	return err;
}


static int output_handler(const char *str)
{
	return print_handler(str, str_len(str), NULL);
}


static struct ui ui_stdio = {
	.name = "stdio",
	.outputh = output_handler
};

static int module_init(void)
{
	int err;
	err = ui_alloc(&ui_state);
	if (err)
		return err;

	ui_register(&ui_stdio);
	return 0;
}


static int module_close(void)
{
	ui_unregister(&ui_stdio);
	ui_state = mem_deref(ui_state);

	return 0;
}

const struct mod_export DECL_EXPORTS(stdio) = {
	"stdio",
	"ui",
	module_init,
	module_close
};
