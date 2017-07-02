/*
Copyright (c) 2010 - 2017, Alfred E. Heggestad
Copyright (c) 2010 - 2017, Richard Aas
Copyright (c) 2010 - 2017, Creytiv.com
All rights reserved.


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <re.h>
#include <everip.h>
#include <string.h>
#include "test.h"


struct test {
	unsigned cmd_called;
};

static int cmd_test(struct re_printf *pf, void *arg)
{
	struct cmd_arg *carg = arg;
	struct test *test = carg->data;
	int err = 0;
	(void)pf;

	ASSERT_EQ('@', carg->key);
	ASSERT_TRUE(NULL == carg->prm);
	ASSERT_EQ(true, carg->complete);

	++test->cmd_called;

 out:
	return err;
}


static const struct cmd cmdv[] = {
	{NULL, '@', 0, "Test command",  cmd_test},
};


static int vprintf_null(const char *p, size_t size, void *arg)
{
	(void)p;
	(void)size;
	(void)arg;
	return 0;
}


static struct re_printf pf_null = {vprintf_null, 0};


int test_cmd(void)
{
	struct commands *commands = NULL;
	struct cmd_ctx *ctx = 0;
	struct test test;
	int err = 0;

	memset(&test, 0, sizeof(test));

	err = cmd_init(&commands);
	ASSERT_EQ(0, err);

	err = cmd_register(commands, cmdv, ARRAY_SIZE(cmdv));
	ASSERT_EQ(0, err);

	/* it is not possible to register same block twice */
	ASSERT_EQ(EALREADY, cmd_register(commands, cmdv, ARRAY_SIZE(cmdv)));

	/* issue a different command */
	err = cmd_process(commands, &ctx, 'h', &pf_null, &test);
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, test.cmd_called);

	/* issue our command, expect handler to be called */
	err = cmd_process(commands, &ctx, '@', &pf_null, &test);
	ASSERT_EQ(0, err);
	ASSERT_EQ(1, test.cmd_called);

	cmd_unregister(commands, cmdv);

	/* verify that context was not created */
	ASSERT_TRUE(NULL == ctx);

 out:
	mem_deref(commands);
	return err;
}


static int long_handler(struct re_printf *pf, void *arg)
{
	struct cmd_arg *carg = arg;
	struct test *test = carg->data;
	int err = 0;
	(void)pf;

	ASSERT_STREQ("123", carg->prm);

	++test->cmd_called;

 out:
	return err;
}


static const struct cmd longcmdv[] = {
	{ "test", 0, 0, "Test Command", long_handler},
};


int test_cmd_long(void)
{
	struct commands *commands = NULL;
	struct test test;
	const struct cmd *cmd;
	static const char *input_str = ":test 123\n";
	struct cmd_ctx *ctx = NULL;
	size_t i;
	int err;

	memset(&test, 0, sizeof(test));

	err = cmd_init(&commands);
	ASSERT_EQ(0, err);

	/* Verify that the command does not exist */
	cmd = cmd_find_long(commands, "test");
	ASSERT_TRUE(cmd == NULL);

	/* Register and verify command */
	err = cmd_register(commands, longcmdv, ARRAY_SIZE(longcmdv));
	ASSERT_EQ(0, err);

	cmd = cmd_find_long(commands, "test");
	ASSERT_TRUE(cmd != NULL);

	/* Feed it some input data .. */

	for (i=0; i<strlen(input_str); i++) {

		err = cmd_process(commands, &ctx, input_str[i],
				  &pf_null, &test);
		ASSERT_EQ(0, err);
	}

	err = cmd_process_long(commands, "test 123", 8, &pf_null, &test);
	ASSERT_EQ(0, err);

	ASSERT_EQ(2, test.cmd_called);

	/* Cleanup .. */

	cmd_unregister(commands, longcmdv);

	cmd = cmd_find_long(commands, "test");
	ASSERT_TRUE(cmd == NULL);

 out:
	mem_deref(commands);
	return err;
}
