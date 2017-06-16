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

#ifndef RELEASE

#ifndef MAGIC
#error "macro MAGIC must be defined"
#endif

/*
 * Any C compiler conforming to C99 or later MUST support __func__
 */
#if __STDC_VERSION__ >= 199901L
#define __MAGIC_FUNC__ (const char *)__func__
#else
#define __MAGIC_FUNC__ __FUNCTION__
#endif


/** Check magic number */
#define MAGIC_DECL uint32_t magic;
#define MAGIC_INIT(s) (s)->magic = MAGIC
#define MAGIC_CHECK(s) \
	if (MAGIC != s->magic) {					\
		warning("%s: wrong magic struct=%p (magic=0x%08x)\n",	\
			__MAGIC_FUNC__, s, s->magic);			\
		BREAKPOINT;						\
	}
#else
#define MAGIC_DECL
#define MAGIC_INIT(s)
#define MAGIC_CHECK(s) do {(void)(s);} while (0);
#endif
