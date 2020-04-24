/*
 * An implementation of committed access rate for Linux iptables
 * (c) 2015 <abc@openwall.com>
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

#ifndef _XT_RATELIMIT_H
#define _XT_RATELIMIT_H

#include <linux/types.h>

enum {
	XT_RATELIMIT_DST	= 1 << 0,
	XT_RATELIMIT_SRC	= 1 << 1,
	XT_RATELIMIT_MODE	= XT_RATELIMIT_DST|XT_RATELIMIT_SRC,

	XT_RATELIMIT_NAME_LEN	= 32,
};

enum {
	OT_ZERO			= 0,
	OT_MATCH		= 1,
	OT_HOTDROP		= 2,
};

struct xt_ratelimit_mtinfo {
	__u32 mode;
	char name[XT_RATELIMIT_NAME_LEN];

	/* valus below only used in kernel */
	struct xt_ratelimit_htable *ht;
};
#endif /* _XT_RATELIMIT_H */
