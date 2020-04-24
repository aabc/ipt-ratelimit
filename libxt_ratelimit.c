/*
 * An implementation of committed access rate for Linux iptables
 * (c) 2015-2017 <abc@openwall.com>
 *
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <arpa/inet.h>
#include "xt_ratelimit.h"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif


static void ratelimit_help(void)
{
	printf(
"ratelimit match options:\n"
"  --ratelimit-set <name>    Name of the ratelimit set to be used.\n"
"                            DEFAULT will be used if none given.\n"
"  --ratelimit-mode <mode>   Address match: src or dst.\n"
"xt_ratelimit by: ABC <abc@openwall.com>.\n");
}

enum {
	O_NAME,
	O_MODE,
};

#define s struct xt_ratelimit_mtinfo
static const struct xt_option_entry ratelimit_opts[] = {
	{.name = "ratelimit-set", .id = O_NAME, .type = XTTYPE_STRING,
	 .flags = XTOPT_MAND | XTOPT_PUT, XTOPT_POINTER(s, name), .min = 1},
	{.name = "ratelimit-mode", .id = O_MODE, .type = XTTYPE_STRING,
	 .flags = XTOPT_MAND},
	XTOPT_TABLEEND,
};
#undef s

static int parse_mode(uint32_t *mode, const char *option_arg)
{
	if (strcasecmp("dst", option_arg) == 0)
		*mode |= XT_RATELIMIT_DST;
	else if (strcasecmp("src", option_arg) == 0)
		*mode |= XT_RATELIMIT_SRC;
	else
		return -1;
	return 0;
}

static void print_mode(unsigned int mode)
{
	/* DST is primary and exclusive with SRC*/
	if (mode & XT_RATELIMIT_DST)
		fputs("dst", stdout);
	else if (mode & XT_RATELIMIT_SRC)
		fputs("src", stdout);
}

static void ratelimit_parse(struct xt_option_call *cb)
{
	struct xt_ratelimit_mtinfo *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_MODE:
			if (parse_mode(&info->mode, cb->arg) < 0)
				xtables_param_act(XTF_BAD_VALUE, "ratelimit",
				    "--ratelimit-mode", cb->arg);
			break;
	}
}

static void ratelimit_init(struct xt_entry_match *match)
{
	struct xt_ratelimit_mtinfo *info = (struct xt_ratelimit_mtinfo *)match->data;

	strncpy(info->name, "DEFAULT", XT_RATELIMIT_NAME_LEN);
	info->name[XT_RATELIMIT_NAME_LEN - 1] = '\0';
	info->mode = 0;
}

static void ratelimit_print(const void *ip, const struct xt_entry_match *match,
    int numeric)
{
	const struct xt_ratelimit_mtinfo *info = (const void *)match->data;

	fputs("ratelimit:", stdout);
	printf(" set %s", info->name);
	fputs(" mode ", stdout);
	print_mode(info->mode);
}

static void ratelimit_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_ratelimit_mtinfo *info = (const void *)match->data;

	if (strcmp("DEFAULT", info->name))
		printf(" --ratelimit-set %s", info->name);
	if (info->mode & XT_RATELIMIT_MODE) {
		fputs(" --ratelimit-mode ", stdout);
		print_mode(info->mode);
	}

}

static struct xtables_match ratelimit_mt_reg[] = {
	{
		.name		= "ratelimit",
		.version	= XTABLES_VERSION,
		.family		= NFPROTO_IPV4,
		.size		= XT_ALIGN(sizeof(struct xt_ratelimit_mtinfo)),
		.userspacesize	= offsetof(struct xt_ratelimit_mtinfo, ht),
		.help		= ratelimit_help,
		.init		= ratelimit_init,
		.print		= ratelimit_print,
		.save		= ratelimit_save,
		.x6_options	= ratelimit_opts,
		.x6_parse	= ratelimit_parse,
	},
	{
		.name		= "ratelimit",
		.version	= XTABLES_VERSION,
		.family		= NFPROTO_IPV6,
		.size		= XT_ALIGN(sizeof(struct xt_ratelimit_mtinfo)),
		.userspacesize	= offsetof(struct xt_ratelimit_mtinfo, ht),
		.help		= ratelimit_help,
		.init		= ratelimit_init,
		.print		= ratelimit_print,
		.save		= ratelimit_save,
		.x6_options	= ratelimit_opts,
		.x6_parse	= ratelimit_parse,
	},
};

void _init(void)
{
	xtables_register_matches(ratelimit_mt_reg, ARRAY_SIZE(ratelimit_mt_reg));
}

