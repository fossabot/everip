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

#include <string.h>
#include <re.h>
#include <everip.h>


static struct list uil;
static struct cmd_ctx *uictx;


static void ui_handler(char key, struct re_printf *pf)
{
	(void)cmd_process(everip_commands(), &uictx, key, pf, NULL);
}


static int stdout_handler(const char *p, size_t size, void *arg)
{
	(void)arg;

	if (1 != fwrite(p, size, 1, stdout))
		return ENOMEM;

	return 0;
}

void ui_register(struct ui *ui)
{
	if (!ui)
		return;

	list_append(&uil, &ui->le, ui);

	debug("ui: %s\n", ui->name);
}

void ui_unregister(struct ui *ui)
{
	if (!ui)
		return;

	list_unlink(&ui->le);
}

void ui_input(char key)
{
	static struct re_printf pf_stdout = {stdout_handler, NULL};

	ui_handler(key, &pf_stdout);
}

void ui_input_key(char key, struct re_printf *pf)
{
	ui_handler(key, pf);
}

void ui_input_str(const char *str)
{
	struct re_printf pf;
	struct pl pl;

	if (!str)
		return;

	pf.vph = stdout_handler;
	pf.arg = NULL;

	pl_set_str(&pl, str);

	(void)ui_input_pl(&pf, &pl);
}


int ui_input_pl(struct re_printf *pf, const struct pl *pl)
{
	struct cmd_ctx *ctx = NULL;
	struct commands *commands = everip_commands();
	size_t i;
	int err = 0;

	if (!pf || !pl)
		return EINVAL;

	for (i=0; i<pl->l; i++) {
		err |= cmd_process(commands, &ctx, pl->p[i], pf, NULL);
	}

	if (pl->l > 1 && ctx)
		err |= cmd_process(commands, &ctx, '\n', pf, NULL);

	return err;
}

void ui_output(const char *fmt, ...)
{
	char buf[512];
	struct le *le;
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = re_vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (n < 0)
		return;

	for (le = uil.head; le; le = le->next) {
		const struct ui *ui = le->data;

		if (ui->outputh)
			ui->outputh(buf);
	}
}


void ui_reset(void)
{
	uictx = mem_deref(uictx);
}


bool ui_isediting(void)
{
	return uictx != NULL;
}


int ui_password_prompt(char **passwordp)
{
	char pwd[64];
	char *nl;
	int err;

	if (!passwordp)
		return EINVAL;

	/* note: blocking UI call */
	fgets(pwd, sizeof(pwd), stdin);
	pwd[sizeof(pwd) - 1] = '\0';

	nl = strchr(pwd, '\n');
	if (nl == NULL) {
		(void)re_printf("Invalid password (0 - 63 characters"
				" followed by newline)\n");
		return EINVAL;
	}

	*nl = '\0';

	err = str_dup(passwordp, pwd);
	if (err)
		return err;

	return 0;
}
