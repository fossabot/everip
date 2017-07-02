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

static void net_change_handler(void *arg)
{
	unsigned *count = arg;
	++*count;
	info("network changed\n");
}


int test_network(void)
{
	struct network *net = NULL;
	unsigned change_count = 0;
	int err;

	err = net_alloc(&net);
	TEST_ERR(err);
	ASSERT_TRUE(net != NULL);

	ASSERT_EQ(AF_INET, net_af(net));

	net_change(net, 1, net_change_handler, &change_count);

	ASSERT_EQ(0, change_count);

	net_force_change(net);

	ASSERT_EQ(1, change_count);

 out:
	mem_deref(net);
	return err;
}
