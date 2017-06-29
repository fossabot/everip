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
#include <stdlib.h>
#include <time.h>

static uint64_t start_ticks;
static time_t start_time;

static int cmd_net_debug(struct re_printf *pf, void *unused)
{
	(void)unused;
	return net_debug(pf, everip_network());
}

static int menu_legal(struct re_printf *pf, void *unused)
{
	(void)unused;
	int err = 0;

#if SIGNED_CLA_LICENSE
	bool show_instructions = false;
#endif

	err |= re_hprintf(pf, "\n[Legal Information]\n");

	err |= re_hprintf(pf,
					  "\n\nconnectFree(R) EVER/IP(R) for %s/%s [%s]\n"
					  "Copyright 2013-2017 Kristopher Tate and connectFree Corporation.\n"
					  "All Rights Reserved. Protected by International Patent Treaties.\n"
					, sys_os_get(), sys_arch_get()
					, EVERIP_VERSION
					);

#if SIGNED_CLA_LICENSE
	err |= re_hprintf(pf, "\n---[THIS SOFTWARE IS LICENSED UNDER CLA/ODA]---\n");

err |= re_hprintf( pf
				 , "\n\nCONNECTFREE(R) EVER/IP(R) END USER LICENSE AGREEMENT\n"
"\n"
"PLEASE READ THE TERMS OF THIS SOFTWARE LICENSE AGREEMENT (\"AGREEMENT\")\n"
"GOVERNING THE USE OF THE SOFTWARE AND RELATED DOCUMENTATION\n"
"(AS FURTHER DEFINED BELOW) CAREFULLY BEFORE USING THE SOFTWARE.\n"
"\n");
err |= re_hprintf( pf
				 , "    1.  Introduction and Acceptance.  This Agreement is a legal agreement\n"
"between you (either an individual or an entity) (“YOU” or “YOUR”) and\n"
"connectFree Corporation (“connectFree”) regarding the use of connectFree’s\n"
"software known as EVER/IP(R), which includes user documentation provided in\n"
"electronic form (together, the \"connectFree Software\").\n"
"\n");
if (show_instructions) {
	err |= re_hprintf( pf
					 , "\nCAREFULLY READ THE TERMS AND CONDITIONS OF THIS AGREEMENT.\n"
	"BY SELECTING THE \"YES\" BUTTON, YOU ARE AGREEING TO BE BOUND BY AND\n"
	"ARE BECOMING A PARTY TO THIS AGREEMENT. IF YOU DO NOT AGREE TO ALL OF THE\n"
	"TERMS OF THIS AGREEMENT, SELECT THE \"NO\" BUTTON AND THE SOFTWARE WILL NOT\n"
	"BE DOWNLOADED OR INSTALLED ON YOUR COMPUTER.\n\n"
	"\n");
}
err |= re_hprintf( pf
				 , "    2.  License Grant.  Subject to the restrictions set forth below, this\n"
"Agreement grants You a non-exclusive, royalty-free, perpetual license to\n"
"download, install and use one (1) copy of the specified version of connectFree\n"
"Software in object code format, for internal purposes only.  You may\n"
"install and use one (1) copy of connectFree Software on a single personal\n"
"computer running a general purpose consumer operating system and that does\n"
"not operate as a server on a network. connectFree Software is \"in use\" on a\n"
"computer when it is loaded into the temporary memory (i.e., RAM) or\n"
"installed into the permanent memory (e.g., hard disk, CD-ROM, or other\n"
"storage device) of that computer.  You understand and agree that connectFree\n"
"will have no obligation to provide any upgrades, updates or fixes to\n"
"connectFree Software.  You further understand and agree that connectFree\n"
"does not provide maintenance for connectFree Software and will not be under any\n"
"obligation to do so.\n"
"\n");
err |= re_hprintf( pf
				 , "    3.  Ownership.  The license granted to You hereunder does not\n"
"constitute a transfer or sale of connectFree’s ownership rights in or to\n"
"connectFree Software.  Except for the license rights granted above, all right,\n"
"title and interest, including all Intellectual Property Rights, in and to\n"
"connectFree Software, and all copies thereof, are owned and retained by\n"
"connectFree or its licensors. \"Intellectual Property Rights\" means any and all\n"
"rights existing from time to time under patent law, copyright law, trade secret\n"
"law, trademark law, unfair competition law, and any and all other\n"
"proprietary rights, and any and all applications, renewals, extensions and\n"
"restorations thereof, now or hereafter in force and effect worldwide.\n"
"connectFree Software is licensed, not sold, to You for use only under the terms\n"
"of this Agreement, and connectFree reserves all rights not expressly granted to\n"
"You.\n"
"\n");
err |= re_hprintf( pf
				 , "    4.  License Restrictions.  YOU MAY NOT RENT, LEASE, SUBLICENSE, SELL,\n"
"ASSIGN, LOAN OR OTHERWISE TRANSFER CONNECTFREE SOFTWARE OR ANY OF YOUR RIGHTS\n"
"AND OBLIGATIONS HEREUNDER.  You may not reverse engineer, decompile, or\n"
"disassemble connectFree Software or attempt to circumvent any technical\n"
"restrictions included in the code, except to the extent the foregoing\n"
"restriction is expressly prohibited by applicable law.  You may not (i)\n"
"remove or destroy any copyright notices or other proprietary markings;\n"
"(ii) modify or adapt connectFree Software, merge connectFree Software into\n"
"another program or create derivative works based on connectFree Software;\n"
"or (iii) provide, lease, lend, use for timesharing or service bureau purposes,\n"
"or otherwise use or allow others to use connectFree Software for the benefit of\n"
"third parties (through the Internet or otherwise).\n"
"\n");
err |= re_hprintf( pf
				 , "    5.  Confidentiality.  You shall hold in the strictest confidence\n"
"connectFree Software and any related materials or information including, but\n"
"not limited to, any technical data, research, product plans or know-how\n"
"provided by connectFree to You, either directly or indirectly in writing,\n"
"orally or by inspection of tangible objects (“Confidential Information”).\n"
"You shall not disclose any Confidential Information to third parties,\n"
"including any of Your employees who do not have a need to know such\n"
"information and You shall take reasonable measures to protect the secrecy\n"
"of, and to avoid disclosure and unauthorized use of, the Confidential\n"
"Information.  You shall immediately notify connectFree in the event of any\n"
"unauthorized or suspected use or disclosure of the Confidential\n"
"Information.\n"
"\n");
err |= re_hprintf( pf
				 , "    6.  Termination.  This Agreement shall be effective upon installation\n"
"of connectFree Software and SHALL TERMINATE UPON THE EARLIER OF: (I) YOUR\n"
"FAILURE TO COMPLY WITH ANY TERM OF THIS AGREEMENT; OR (II) DESTRUCTION OR\n"
"DELETION OF ALL COPIES OF CONNECTFREE SOFTWARE IN YOUR POSSESSION.\n"
"connectFree’s rights and Your obligations shall survive the termination of this\n"
"Agreement. Upon termination of this Agreement by connectFree, You shall\n"
"certify in writing to connectFree that all copies off connectFree Software,\n"
"or any portion thereof, have either been returned to connectFree or otherwise\n"
"destroyed or deleted from any of Your computer libraries or storage\n"
"devices.\n"
"\n");
err |= re_hprintf( pf
				 , "    7.  NO WARRANTIES.  TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW,\n"
"CONNECTFREE AND ITS LICENSORS PROVIDE THE SOFTWARE \"AS IS\" AND WITHOUT\n"
"WARRANTY OF ANY KIND AND EXPRESSLY DISCLAIMS WITH RESPECT TO THE SOFTWARE\n"
"ALL WARRANTIES AND CONDITIONS, WHETHER EXPRESS, IMPLIED, OR STATUTORY,\n"
"INCLUDING, BUT NOT LIMITED TO, ANY WARRANTIES, DUTIES OR CONDITIONS OF OR\n"
"RELATED TO: MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,\n"
"CORRESPONDENCE TO DESCRIPTION, NON-INFRINGEMENT OF THIRD PARTY RIGHTS,\n"
"LACK OF VIRUSES, ACCURACY OR COMPLETENESS OF RESPONSES, RESULTS,\n"
"WORKMANLIKE EFFORT AND LACK OF NEGLIGENCE. ALSO, THERE IS NO WARRANTY,\n"
"DUTY OR CONDITION OF TITLE, QUIET ENJOYMENT, OR QUIET POSSESSION. YOU ARE\n"
"SOLELY RESPONSIBLE FOR ANY DAMAGE TO YOUR COMPUTER, MOBILE DEVICE, OR ANY\n"
"OTHER DEVICE, OR LOSS OF DATA THAT RESULTS FROM YOUR USE OF THE SOFTWARE.\n"
"\n");
err |= re_hprintf( pf
				 , "    8.  LIMITATION OF LIABILITY. UNDER NO CIRCUMSTANCES WILL CONNECTFREE BE\n"
"LIABLE FOR ANY CONSEQUENTIAL, SPECIAL, INDIRECT, INCIDENTAL OR PUNITIVE\n"
"DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF\n"
"BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF BUSINESS INFORMATION,\n"
"LOSS OF DATA OR OTHER SUCH PECUNIARY LOSS) ARISING OUT OF THE USE OR\n"
"INABILITY TO USE THE SOFTWARE, EVEN IF CONNECTFREE HAS BEEN ADVISED OF THE\n"
"POSSIBILITY OF SUCH DAMAGES.   IN NO EVENT SHALL CONNECTFREE’S AGGREGATE\n"
"LIABILITY FOR DAMAGES ARISING OUT OF THIS AGREEMENT EXCEED THE GREATOR OF\n"
"(1) THE AMOUNT PAID TO CONNECTFREE FOR THE SOFTWARE UNDER THIS AGREEMENT\n"
"OR (2) ¥10000JPY.\n"
"\n");
err |= re_hprintf( pf
				 , "    9.  INDEMNITY.  You agree to defend, indemnify and hold harmless\n"
"connectFree, its officers, directors, employees, and agents, from and against\n"
"any and all claims, damages, obligations, losses, liabilities, costs or\n"
"debt, and expenses (including but not limited to attorney's fees) arising\n"
"from: (i) Your use of and access to connectFree Software; (ii) Your violation\n"
"of any of the terms of this Agreement; or (iii) Your violation of any\n"
"third party right, including without limitation any copyright, property,\n"
"or privacy right, arising out of Your use of and access to connectFree\n"
"Software.  This defense and indemnification obligation will survive this\n"
"Agreement and Your use of connectFree Software.\n"
"\n");
err |= re_hprintf( pf
				 , "    10. Export Restrictions.  You may not export or re-export: (i) connectFree\n"
"Software without the prior written consent of connectFree; and (ii) connectFree\n"
"Software without complying with applicable export control laws and\n"
"obtaining any necessary permits and licenses.\n"
"\n");
err |= re_hprintf( pf
				 , "    12. Changes to the terms of this Agreement.  connectFree may make changes\n"
"to this Agreement from time to time. When these changes are made, connectFree\n"
"will make any new/additional terms available to You.  You understand and\n"
"agree that if You use connectFree Software after the date on which terms have\n"
"changed, connectFree will treat Your use as acceptance of the new/additional\n"
"terms.\n"
"\n");
err |= re_hprintf( pf
				 , "    13. General.  This Agreement is governed by the laws of the nation state\n"
"of Japan, excluding its conflicts of laws principles.  You agree to the\n"
"exclusive jurisdiction and venue of the prefecture and federal courts located\n"
"in Kyoto-shi, Kyoto-fu, JAPAN.  If any provision of this Agreement is held by\n"
"a court of competent jurisdiction to be contrary to law, such provision shall\n"
"be changed and interpreted so as to best accomplish the objectives of the\n"
"original provision to the fullest extent allowed by law and the remaining\n"
"provisions of this Agreement shall remain in full force and effect. The\n"
"headings in this Agreement are inserted for convenience only and do not affect\n"
"its interpretation.  You may not assign this Agreement, whether by operation\n"
"of law, merger or reorganization, without the prior written consent of\n"
"connectFree; any attempted assignment in violation of the foregoing will be\n"
"void.  connectFree may assign this Agreement in connection with a\n"
"reorganization, reincorporation, merger, or sale of all, or substantially\n"
"all of the shares or assets of connectFree.  This Agreement constitutes the\n"
"final, complete and exclusive agreement between the parties with respect to\n"
"Your use of connectFree Software and supersedes any prior or contemporaneous\n"
"representations or agreements, whether written or oral. Any company names,\n"
"logos, and product names displayed in connectFree Software are subject to\n"
"Japanese and international copyright, trademark and intellectual property laws\n"
"and You may not reproduce or distribute any such company names, logos or\n"
"product names without the express written consent of their respective owners.\n"
"\n");
err |= re_hprintf( pf
				 , "    14. Questions.  Should You have any questions concerning this\n"
"Agreement, or if You desire to contact connectFree for any reason,\n"
"please visit http://connectfree.co.jp/\n"
"\n\n");
if (show_instructions) {
	err |= re_hprintf( pf
					 , "BY SELECTING THE “YES” BUTTON BELOW, YOU ARE INDICATING THAT YOU HAVE READ\n"
	"AND CONSENT TO BE BOUND BY THE TERMS OF THIS AGREEMENT.  IF YOU HAVE NOT\n"
	"READ THIS AGREEMENT, OR YOU DO NOT AGREE TO BE LEGALLY BOUND BY ITS TERMS,\n"
	"SELECT “NO” AND DO NOT USE THE SOFTWARE.\n\n"
	);
}

	err |= re_hprintf(pf, "\n\n--[END OF EULA]--\n\n");

#endif

	err |= re_hprintf(pf, "\n\nAcknowledgements:\n");

	err |= re_hprintf(pf, "\nPortions of this ConnectFree Software may utilize the following\n"
					"copyrighted material, the use of which is hereby acknowledged.\n");

	err |= re_hprintf(pf, "\n\nAlfred E. Heggestad (libre)\n"
"Copyright (c) 2010 - 2016, Alfred E. Heggestad\n"
"Copyright (c) 2010 - 2016, Richard Aas\n"
"Copyright (c) 2010 - 2016, Creytiv.com\n"
"All rights reserved.\n"
"\n"
"\n"
"Redistribution and use in source and binary forms, with or without\n"
"modification, are permitted provided that the following conditions\n"
"are met:\n"
"\n"
"1. Redistributions of source code must retain the above copyright\n"
"   notice, this list of conditions and the following disclaimer.\n"
"\n"
"2. Redistributions in binary form must reproduce the above copyright\n"
"   notice, this list of conditions and the following disclaimer in the\n"
"   documentation and/or other materials provided with the distribution.\n"
"\n"
"3. Neither the name of the Creytiv.com nor the names of its contributors\n"
"   may be used to endorse or promote products derived from this software\n"
"   without specific prior written permission.\n"
"\n"
"\n"
"THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR\n"
"IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n"
"OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.\n"
"IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,\n"
"INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n"
"NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
"DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
"THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF\n"
"THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
);

	err |= re_hprintf(pf, "\n\nFrank Denis (libsodium)\n"
"ISC License\n"
"\n"
"Copyright (c) 2013-2017\n"
"Frank Denis <j at pureftpd dot org>\n"
"\n"
"Permission to use, copy, modify, and/or distribute this software for any\n"
"purpose with or without fee is hereby granted, provided that the above\n"
"copyright notice and this permission notice appear in all copies.\n"
"\n"
"THE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES\n"
"WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF\n"
"MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR\n"
"ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES\n"
"WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN\n"
"ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF\n"
"OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.\n\n");

err |= re_hprintf(pf, "\n\n--[END]--\n\n");

	return err;
}

static int print_system_info(struct re_printf *pf, void *arg)
{
	uint32_t uptime;
	int err = 0;

	(void)arg;

	uptime = (uint32_t)((long long)(tmr_jiffies() - start_ticks)/1000);

	err |= re_hprintf(pf, "\n---[SYSTEM]---\n");

	err |= re_hprintf(pf, " MACHINE:  %s/%s\n", sys_arch_get(),
			  sys_os_get());
	err |= re_hprintf(pf, " VERSION:  %s (cflib v%s)\n",
			  EVERIP_VERSION, sys_libre_version_get());
	err |= re_hprintf(pf, " BUILD:    %H\n", sys_build_get, NULL);
	err |= re_hprintf(pf, " KERNEL:   %H\n", sys_kernel_get, NULL);
	err |= re_hprintf(pf, " UPTIME:   %H\n", fmt_human_time, &uptime);
	err |= re_hprintf(pf, " STARTED:  %s", ctime(&start_time));

#ifdef __VERSION__
	err |= re_hprintf(pf, " COMPILER: %s\n", __VERSION__);
#endif

	return err;
}

static int cmd_conduits_debug(struct re_printf *pf, void *unused)
{
	(void)unused;
	return conduits_debug(pf, everip_conduits());
}

static int cmd_treeoflife_debug(struct re_printf *pf, void *unused)
{
	(void)unused;
	return treeoflife_debug(pf, everip_treeoflife());
}

static int cmd_treeoflife_dht_debug(struct re_printf *pf, void *unused)
{
	(void)unused;
	return treeoflife_dht_debug(pf, everip_treeoflife());
}

static int cmd_caengine_debug(struct re_printf *pf, void *unused)
{
	(void)unused;
	return caengine_debug(pf, everip_caengine());
}

static const struct cmd debugcmdv[] = {
{"main",     0,       0, "Main loop debug",          re_debug             },
{"modules",  0,       0, "Loaded Module List",             mod_debug            },
{"net", 	'n',      0, "Network Information",            cmd_net_debug        },
{"sys", 	's',      0, "System Information",              print_system_info    },
{"timers",   0,       0, "Timer debug",              tmr_status           },
{"memstat", 'm',      0, "Memory status",            mem_status           },
{"legal", 0,      0, "Legal Information",            menu_legal           },
{"peers", 'p',      0, "Peers and Conduits",            cmd_conduits_debug },
{"tree", 't',      0, "Routing Tree Information",            cmd_treeoflife_debug },
{"dht", 'd',      0, "DHT Database",            cmd_treeoflife_dht_debug },
{"crypto", 'c',      0, "Crypto-Authentication (CA) Engine",            cmd_caengine_debug },

};


static int module_init(void)
{
	int err;

	start_ticks = tmr_jiffies();
	(void)time(&start_time);

	err = cmd_register(everip_commands(),
			   debugcmdv, ARRAY_SIZE(debugcmdv));

	return err;
}


static int module_close(void)
{
	cmd_unregister(everip_commands(), debugcmdv);

	return 0;
}


const struct mod_export DECL_EXPORTS(dcmd) = {
	"dcmd",
	"app",
	module_init,
	module_close
};
