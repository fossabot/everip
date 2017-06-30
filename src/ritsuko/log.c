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

/* logging similar to ntkernel */
static struct {
	struct list logl;
	bool debug;
	bool info;
	bool stder;
} lg = {
	LIST_INIT,
	false, /* debug */
	true,
	true
};


void log_register_handler(struct log *log)
{
	if (!log)
		return;

	list_append(&lg.logl, &log->le, log);
}


void log_unregister_handler(struct log *log)
{
	if (!log)
		return;

	list_unlink(&log->le);
}


void log_enable_debug(bool enable)
{
	lg.debug = enable;
}


void log_enable_info(bool enable)
{
	lg.info = enable;
}


void log_enable_stderr(bool enable)
{
	lg.stder = enable;
}


void vlog(enum log_level level, const char *fmt, va_list ap)
{
	char buf[4096];
	struct le *le;

	if (re_vsnprintf(buf, sizeof(buf), fmt, ap) < 0)
		return;

	if (lg.stder) {

#if !defined(WIN32) && !defined(CYGWIN)
		bool color = true;

		if (level == LEVEL_ERROR) {
			(void)re_fprintf(stderr, "\x1b[31m"); /* Red */
		} else if (level == LEVEL_WARN) {
			(void)re_fprintf(stderr, "\x1b[33m"); /* Yellow */
		} else if (level == LEVEL_INFO) {
			(void)re_fprintf(stderr, "\x1b[34m"); /* Blue */
		} else if (level == LEVEL_DEBUG) {
			(void)re_fprintf(stderr, "\x1b[1;35m"); /* Purple */
		} else {
			color = false;
		}

		(void)re_fprintf(stderr, "%s", buf);

		if (color)
			(void)re_fprintf(stderr, "\x1b[;m");
#else
		/* windowz has no color... */
		(void)re_fprintf(stderr, "%s", buf);
#endif
	}

	le = lg.logl.head;

	while (le) {

		struct log *log = le->data;
		le = le->next;

		if (log->h)
			log->h(level, buf);
	}
}


void loglv(enum log_level level, const char *fmt, ...)
{
	va_list ap;

	if ((LEVEL_DEBUG == level) && !lg.debug)
		return;

	if ((LEVEL_INFO == level) && !lg.info)
		return;

	va_start(ap, fmt);
	vlog(level, fmt, ap);
	va_end(ap);
}


void debug(const char *fmt, ...)
{
	va_list ap;

	if (!lg.debug)
		return;

	va_start(ap, fmt);
	vlog(LEVEL_DEBUG, fmt, ap);
	va_end(ap);
}


void info(const char *fmt, ...)
{
	va_list ap;

	if (!lg.info)
		return;

	va_start(ap, fmt);
	vlog(LEVEL_INFO, fmt, ap);
	va_end(ap);
}


void warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(LEVEL_WARN, fmt, ap);
	va_end(ap);
}


void error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(LEVEL_ERROR, fmt, ap);
	va_end(ap);
}
