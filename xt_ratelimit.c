/*
 * An implementation of committed access rate for Linux iptables
 * (c) 2015-2020 <abc@openwall.com>
 *
 * Based on xt_hashlimit and in lesser extent on xt_recent.
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include "compat.h"
#include "xt_ratelimit.h"

#define XT_RATELIMIT_VERSION "0.3.3"
#include "version.h"
#ifdef GIT_VERSION
# undef XT_RATELIMIT_VERSION
# define XT_RATELIMIT_VERSION GIT_VERSION
#endif

MODULE_AUTHOR("<abc@openwall.com>");
MODULE_DESCRIPTION("iptables ratelimit policer mt module");
MODULE_LICENSE("GPL");
MODULE_VERSION(XT_RATELIMIT_VERSION);
MODULE_ALIAS("ipt_ratelimit");
MODULE_ALIAS("ip6t_ratelimit");

#define RATE_ESTIMATOR			/* average rate estimator */

static unsigned int hashsize __read_mostly = 10000;
module_param(hashsize, uint, 0400);
MODULE_PARM_DESC(hashsize, "default size of hash table used to look up IPs");

/* There is five code paths:
 *  AA module load/unload
 *  BB iptables match insertion/deletion
 *  CC ratelimit rule insertion/deletion
 *  DD packet processing
 *  EE statistics
 */
static DEFINE_MUTEX(ratelimit_mutex); /* htable lists management */

/* net namespace support */
struct ratelimit_net {
        struct hlist_head	htables;
        struct proc_dir_entry	*ipt_ratelimit;
};

/* CAR accounting */
struct ratelimit_car {
	unsigned long last;		/* last refill (jiffies) */
	u32 tc;				/* committed token bucket counter */
	u32 te;				/* exceeded token bucket counter */

	u32 cbs;			/* committed burst size (bytes) */
	u32 ebs;			/* extended burst size (bytes) */
	u32 cir;			/* committed information rate (bits/s) / (HZ * 8) */
};

/* stat not related to policing */
struct ratelimit_stat {
	atomic64_t green_bytes;
	atomic64_t red_bytes;
	atomic_t green_pkt;
	atomic_t red_pkt;

#ifdef RATE_ESTIMATOR
#define RATEST_SECONDS 4		/* length of rate estimator time slot */
#define RATEST_JIFFIES (HZ * RATEST_SECONDS)
	u64 cur_s_bytes;		/* accumulator at current time slot */
	u64 prev_s_bytes;		/* accumulator at previous slot */
	unsigned int est_slot;		/* current time slot */
#endif
};

/* hash bucket match entry */
struct ratelimit_match {
	struct hlist_node node;		/* hash bucket list */
	u8 family;
	u8 prefix;
	union nf_inet_addr addr;
	struct ratelimit_ent *ent;	/* owner struct, where they are stored in array */
};

/* set entity: can have many IPs */
struct ratelimit_ent {
	struct rcu_head rcu;		/* destruction call list */
	int mtcnt;			/* size of matches[mtcnt] */
	struct ratelimit_stat stat;
	struct ratelimit_car car;
	spinlock_t lock_bh;

	/* variable sized array to store actual hash match entries (instead of
	 * a list) belonging to a single policing entity */
	struct ratelimit_match matches[0];
};

#define MAX_PREFIX4 32
#define NUM_PREFIX4 (MAX_PREFIX4 + 1)
#define MAX_PREFIX6 128
#define NUM_PREFIX6 (MAX_PREFIX6 + 1)
#define MAX_PREFIX  MAX_PREFIX6
#define NUM_PREFIX  NUM_PREFIX6

/* per-net named hash table, locked with ratelimit_mutex */
struct xt_ratelimit_htable {
	struct hlist_node node;		/* all htables */
	int use;			/* references from iptables */
	spinlock_t lock;		/* write access to hash */
	unsigned int mt_count;		/* currently matches in the hash */
	unsigned int ent_count;		/* currently entities linked */
	unsigned int size;		/* hash array size, set from hashsize */
	int other;			/* what to do with 'other' packets */
	struct net *net;		/* for destruction */
	struct proc_dir_entry *pde;
	char name[XT_RATELIMIT_NAME_LEN];
	int prefix_count[NUM_PREFIX];	/* housekeeping of bitmask */
	DECLARE_BITMAP(prefix_bitmap, NUM_PREFIX);
	struct hlist_head hash[0];	/* rcu lists array[size] of ratelimit_match'es */
};

static int ratelimit_net_id;
/* return pointer to per-net-namespace struct */
static inline struct ratelimit_net *ratelimit_pernet(struct net *net)
{
        return net_generic(net, ratelimit_net_id);
}

#ifdef RATE_ESTIMATOR
unsigned long calc_rate_est(const struct ratelimit_stat *stat)
{
	const unsigned long now = jiffies;
	const unsigned int est_slot = now / RATEST_JIFFIES;
	unsigned long bps;
	unsigned long cur_bytes = 0;

	/* init 'bps' to previous slot bytes size */
	if (est_slot == stat->est_slot) {
		bps = stat->prev_s_bytes;
		cur_bytes = stat->cur_s_bytes;
	} else if ((est_slot - 1) == stat->est_slot)
		bps = stat->cur_s_bytes;
	else
		return 0;

	{
		const unsigned int slot_delta_rtime = RATEST_JIFFIES - (now % RATEST_JIFFIES);
#define SMOOTH_VAUE 10 /* smoothen integer arithmetic */
		const unsigned int prev_ratio = RATEST_JIFFIES * SMOOTH_VAUE / slot_delta_rtime;

		bps = bps * SMOOTH_VAUE / prev_ratio;
		bps += cur_bytes;
		return bps * BITS_PER_BYTE / RATEST_SECONDS;
	}
}
#endif
#define SAFEDIV(x,y) ((y)? ({ u64 __tmp = x; do_div(__tmp, y); (unsigned int)__tmp; }) : 0)

static int ratelimit_seq_ent_show(struct ratelimit_match *mt,
    struct seq_file *s)
{
	struct ratelimit_ent *ent = mt->ent;
	int i;

	/* to print entities only once, we print only entities
	 * where match is first element */
	if (&ent->matches[0] != mt)
		return 0;

	/* lock for consistent reads from the counters */
	spin_lock_bh(&ent->lock_bh);
	for (i = 0; i < ent->mtcnt; i++) {
		struct ratelimit_match *mti = &ent->matches[i];

		if (mti->family == AF_INET6) {
			seq_printf(s, "%s%pI6c", i == 0? "" : ",", &mti->addr);
			if (mti->prefix != 128)
				seq_printf(s, "/%d", mti->prefix);
		} else {
			seq_printf(s, "%s%pI4", i == 0? "" : ",", &mti->addr);
			if (mti->prefix != 32)
				seq_printf(s, "/%d", mti->prefix);
		}
	}
	seq_printf(s, " cir %u cbs %u ebs %u;",
	    ent->car.cir * (HZ * BITS_PER_BYTE), ent->car.cbs, ent->car.ebs);

	seq_printf(s, " tc %u te %u last", ent->car.tc, ent->car.te);
	if (ent->car.last)
		seq_printf(s, " %ld;", jiffies - ent->car.last);
	else
		seq_printf(s, " never;");

	seq_printf(s, " conf %u/%llu",
	    (u32)atomic_read(&ent->stat.green_pkt),
		 (u64)atomic64_read(&ent->stat.green_bytes));

#ifdef RATE_ESTIMATOR
	seq_printf(s, " %lu bps", calc_rate_est(&ent->stat));
#endif

	seq_printf(s, ", rej %u/%llu",
	    (u32)atomic_read(&ent->stat.red_pkt),
		 (u64)atomic64_read(&ent->stat.red_bytes));

	seq_printf(s, "\n");

	spin_unlock_bh(&ent->lock_bh);
	return seq_has_overflowed(s);
}

static int ratelimit_seq_show(struct seq_file *s, void *v)
{
	struct xt_ratelimit_htable *ht = s->private;
	unsigned int *bucket = (unsigned int *)v;
	struct ratelimit_match *mt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *pos;
#endif

	/* print everything from the bucket at once */
	if (!hlist_empty(&ht->hash[*bucket])) {
		compat_hlist_for_each_entry(mt, pos, &ht->hash[*bucket], node)
			if (ratelimit_seq_ent_show(mt, s))
				return -1;
	}
	return 0;
}

static void *ratelimit_seq_start(struct seq_file *s, loff_t *pos)
	__acquires(&ht->lock)
{
	struct xt_ratelimit_htable *ht = s->private;
	unsigned int *bucket;

	spin_lock(&ht->lock);
	if (*pos >= ht->size)
		return NULL;

	bucket = kmalloc(sizeof(unsigned int), GFP_ATOMIC);
	if (!bucket)
		return ERR_PTR(-ENOMEM);

	*bucket = *pos;
	return bucket;
}

static void *ratelimit_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct xt_ratelimit_htable *ht = s->private;
	unsigned int *bucket = (unsigned int *)v;

	*pos = ++(*bucket);
	if (*pos >= ht->size) {
		kfree(v);
		return NULL;
	}
	return bucket;
}

static void ratelimit_seq_stop(struct seq_file *s, void *v)
	__releases(&ht->lock)
{
	struct xt_ratelimit_htable *ht = s->private;
	unsigned int *bucket = (unsigned int *)v;

	if (!IS_ERR(bucket))
		kfree(bucket);
	spin_unlock(&ht->lock);
}

static const struct seq_operations ratelimit_seq_ops = {
	.start		= ratelimit_seq_start,
	.show		= ratelimit_seq_show,
	.next		= ratelimit_seq_next,
	.stop		= ratelimit_seq_stop,
};

static int ratelimit_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &ratelimit_seq_ops);

	if (!ret) {
		struct seq_file *sf = file->private_data;
		sf->private = PDE_DATA(inode);
	}
	return ret;
}

static inline u32 bits2mask(int bits) {
	return (bits? 0xffffffff << (32 - bits) : 0);
}

static void ratelimit_table_flush(struct xt_ratelimit_htable *ht);
static struct ratelimit_ent *ratelimit_ent_zalloc(int msize);
static inline struct ratelimit_ent *ratelimit_match_find(const struct xt_ratelimit_htable *ht, const __be32 addr, const u8 prefix);
static inline struct ratelimit_ent *ratelimit_match_find6(const struct xt_ratelimit_htable *ht, const union nf_inet_addr *addr, const u8 prefix);
static void ratelimit_ent_add(struct xt_ratelimit_htable *ht, struct ratelimit_ent *ent);
static void ratelimit_ent_del(struct xt_ratelimit_htable *ht, struct ratelimit_ent *ent);

/* convert ipv4 or ipv6 address string into struct sockaddr */
int in_pton(const char *src, int srclen, struct sockaddr_storage *dst, int delim, const char **end)
{
	if (in4_pton(src, srclen, (u8 *)&((struct sockaddr_in *)dst)->sin_addr, delim, end)) {
		dst->ss_family = AF_INET;
		return 1;
	} else if (in6_pton(src, srclen, (u8 *)&((struct sockaddr_in6 *)dst)->sin6_addr, delim, end)) {
		dst->ss_family = AF_INET6;
		return 1;
	} else
		return 0;
}

static __be32 set_netmask(short prefix)
{
	if (prefix <= 0)
		return 0;
	else if (prefix >= 32)
		return 0xffffffff;
	else
		return htonl(0xffffffff << (32 - prefix));
}

static void set_mask6(union nf_inet_addr *ip, u8 prefix)
{
	ip->ip6[0] = set_netmask((short)prefix);
	ip->ip6[1] = set_netmask((short)prefix - 32);
	ip->ip6[2] = set_netmask((short)prefix - 64);
	ip->ip6[3] = set_netmask((short)prefix - 96);
}

static int parse_rule(struct xt_ratelimit_htable *ht, char *str, size_t size)
{
	char * const buf = str; /* for logging only */
	const char *p;
	const char * const endp = str + size;
	struct ratelimit_ent *ent;	/* new entry */
	struct ratelimit_ent *ent_chk;	/* old entry */
	struct sockaddr_storage addr;
	int ent_size;
	int add;
	int i;
	int ptok = 0;
	int warn = 1;

	/* make sure that size is enough for two decrements */
	if (size < 2 || !str || !ht)
		return -EINVAL;

	/* strip trailing newline for better formatting of error messages */
	str[--size] = '\0';

	/* rule format is: +address[,address...] [keyword value]...
	 * address set is unique key for parameters,
	 * address should not duplicate */
	if (*str == '@') {
		warn = 0; /* hide redundant deletion warning */
		++str;
		--size;
	}
	if (size < 1)
		return -EINVAL;
	switch (*str) {
		case '\n':
		case '#':
			return 0;
		case '/': /* flush table */
			ratelimit_table_flush(ht);
			return 0;
		case ':':
			++str;
			--size;
			if (strcmp(str, "hotdrop") == 0)
				ht->other = OT_HOTDROP;
			else if (strcmp(str, "match") == 0)
				ht->other = OT_MATCH;
			else if (strcmp(str, "nomatch") == 0)
				ht->other = OT_ZERO;
			else if (strcmp(str, "flush") == 0)
				ratelimit_table_flush(ht);
			else
				return -EINVAL;
			return 0;
		case '-':
			add = false;
			break;
		case '+':
			add = true;
			break;
		default:
			pr_err("Rule should start with '+', '-', or '/'\n");
			return -EINVAL;
	}
	++str;
	--size;

	/* determine address set size */
	ent_size = 0;
	for (p = str;
	    p < endp && *p && (ptok = in_pton(p, size - (p - str), &addr, -1, &p));
	    ++p) {
		++ent_size;
		if ((p + 1) < endp && *p == '/')
			for (++p; p < endp && *p >= '0' && *p <= '9'; ++p);
		if (p >= endp || !*p || *p == ' ')
			break;
		else if (*p != ',') {
			pr_err("IP addresses should be separated with ',' (cmd: %s)\n", buf);
			return -EINVAL;
		}
	}
	if (!ptok || (p < endp && *p && *p != ' ') || !ent_size) {
		pr_err("Invalid IP address list (cmd: %s)\n", buf);
		return -EINVAL;
	}

	/* prepare ent */
	ent = ratelimit_ent_zalloc(ent_size);
	if (!ent)
		return -ENOMEM;

	spin_lock_init(&ent->lock_bh);
	for (i = 0, p = str;
	    p < endp && *p && in_pton(p, size - (p - str), &addr, -1, &p);
	    ++p, ++i) {
		struct ratelimit_match *mt = &ent->matches[i];
		int j;
		unsigned int prefix = -1;
		const char *pref;
		union nf_inet_addr mask;

		BUG_ON(i >= ent_size);
		if ((p + 1) < endp && *p == '/') {
			for (++p, pref = p; p < endp && *p >= '0' && *p <= '9'; ++p);
			prefix = simple_strtoul(pref, NULL, 10);
		}
		mt->family = addr.ss_family;
		if (mt->family == AF_INET6) {
			if (prefix > 128)
				prefix = 128;
			memcpy(mt->addr.ip6, &((struct sockaddr_in6 *)&addr)->sin6_addr, sizeof(mt->addr.ip6));
		} else {
			if (prefix > 32)
			       prefix = 32;
			mt->addr.ip = ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
		}

		/* following works both for ip and ip6, also cleaning stale bits,
		 * and they assumed to be clean in the below memcmp */
		set_mask6(&mask, prefix);
		for (j = 0; j < ARRAY_SIZE(mt->addr.ip6); ++j)
			mt->addr.ip6[j] &= mask.ip6[j];

		mt->prefix = prefix;
		mt->ent = ent;
		++ent->mtcnt;
		/* there should not be duplications,
		 * this is also important for below test of mtcnt */
		for (j = 0; j < i; ++j)
			if (ent->matches[j].family == mt->family &&
			    !memcmp(ent->matches[j].addr.ip6, mt->addr.ip6, sizeof(mt->addr.ip6))) {
				pr_err("Duplicated IP address %pISc in list (cmd: %s)\n", &addr, buf);
				kvfree(ent);
				return -EINVAL;
			}
		if (p >= endp || !*p || *p == ' ')
			break;
	}
	BUG_ON(ent->mtcnt != ent_size);

	/* parse parameters */
	str = (char *)p; /* strip const, also reset 'str' */
	if (add) /* unindented */
	for (i = 0; p < endp && *p; ++i) {
		const char *v;
		unsigned int val;

		while (p < endp && *p == ' ')
			++p;
		v = p;
		while (p < endp && *p && *p != ' ')
			++p;
		if (v == p) {
			if (i == 0) {
				/* error if no parameters */
				pr_err("Add op should have arguments (cmd: %s)\n", buf);
				kvfree(ent);
				return -EINVAL;
			} else
				break;
		}
		val = simple_strtoul(v, NULL, 10);
		switch (i) {
			case 0:
				ent->car.cir = val / (HZ * BITS_PER_BYTE);
				/* autoconfigure optimal parameters */
				val = val / 8 + (val / 8 / 2);
				/* FALLTHROUGH */
			case 1:
				ent->car.cbs = val;
				val *= 2;
				/* FALLTHROUGH */
			case 2:
				ent->car.ebs = val;
		}
	}
	if (add && str == p) {
		pr_err("Add op should have arguments (cmd: %s)\n", buf);
		kvfree(ent);
		return -EINVAL;
	}

	spin_lock(&ht->lock);
	/* check existence of these IPs */
	ent_chk = NULL;
	for (i = 0; i < ent->mtcnt; ++i) {
		struct ratelimit_match *mt = &ent->matches[i];
		struct ratelimit_ent *tent;

		if (mt->family == AF_INET6)
			tent = ratelimit_match_find6(ht, &mt->addr, mt->prefix);
		else
			tent = ratelimit_match_find(ht, mt->addr.ip, mt->prefix);
		if (!ent_chk)
			ent_chk = tent;
		if (tent != ent_chk) {
			/* no operation should reference multiple entries */
			if (mt->family == AF_INET6)
				pr_err("IP address %pI6c from multiple rules (cmd: %s)\n",
				    &mt->addr,  buf);
			else
				pr_err("IP address %pI4 from multiple rules (cmd: %s)\n",
				    &mt->addr,  buf);
			goto unlock_einval;
		}
	}

	if (add) {
		/* add op should not reference any existing entries */
		/* unless it's update op (which is quiet add) */
		if (warn && ent_chk) {
			pr_err("Add op references existing address (cmd: %s)\n", buf);
			goto unlock_einval;
		}
	} else {
		/* delete op should reference something, and its size
		 * should be equal (this is correct, because duplications
		 * inside of set(s) are impossible) */
		if (!ent_chk) {
			if (warn) {
				pr_err("Del op doesn't reference any existing address (cmd: %s)\n", buf);
				goto unlock_einval;
			}
			goto retok;
		}
		if (ent_chk->mtcnt != ent->mtcnt) {
			pr_err("Del op doesn't match other rule set fully (cmd: %s)\n", buf);
			goto unlock_einval;
		}
	}

	if (add) {
		if (ent_chk) {
			/* update */
			spin_lock_bh(&ent_chk->lock_bh);
			ent_chk->car = ent->car;
			spin_unlock_bh(&ent_chk->lock_bh);
		} else {
			ratelimit_ent_add(ht, ent);
			ent = NULL;
		}
	} else
		ratelimit_ent_del(ht, ent_chk);

retok:
	spin_unlock(&ht->lock);

	if (ent)
		kvfree(ent);
	return 0;

unlock_einval:
	spin_unlock(&ht->lock);
	kvfree(ent);
	return -EINVAL;
}

static char proc_buf[4000];

static ssize_t
ratelimit_proc_write(struct file *file, const char __user *input,
    size_t size, loff_t *loff)
{
	struct xt_ratelimit_htable *ht = PDE_DATA(file_inode(file));
	char *p;

	if (!size || !input | !ht)
		return 0;
	if (size > sizeof(proc_buf))
		size = sizeof(proc_buf);
	if (copy_from_user(proc_buf, input, size) != 0)
		return -EFAULT;

	for (p = proc_buf; p < &proc_buf[size]; ) {
		char *str = p;

		while (p < &proc_buf[size] && *p != '\n')
			++p;
		if (p == &proc_buf[size] || *p != '\n') {
			/* unterminated command */
			if (str == proc_buf) {
				pr_err("Rule should end with '\\n'\n");
				return -EINVAL;
			} else {
				/* Rewind to the beginning of incomplete
				 * command for smarter writers, this doesn't
				 * help for `cat`, though. */
				p = str;
				break;
			}
		}
		++p;
		if (parse_rule(ht, str, p - str))
			return -EINVAL;
	}

	*loff += p - proc_buf;
	return p - proc_buf;
}

#ifdef DEFINE_PROC_SHOW_ATTRIBUTE
static const struct proc_ops ratelimit_fops = {
	.proc_open	= ratelimit_proc_open,
	.proc_read	= seq_read,
	.proc_write	= ratelimit_proc_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};
#else
static const struct file_operations ratelimit_fops = {
	.owner		= THIS_MODULE,
	.open		= ratelimit_proc_open,
	.read		= seq_read,
	.write		= ratelimit_proc_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
#endif

/* allocate named hash table, register its proc entry */
static int htable_create(struct net *net, struct xt_ratelimit_mtinfo *minfo)
	/* rule insertion chain, under ratelimit_mutex */
{
        struct ratelimit_net *ratelimit_net = ratelimit_pernet(net);
        struct xt_ratelimit_htable *ht;
        unsigned int hsize = hashsize; /* (entities) */
	unsigned int sz; /* (bytes) */
	int i;

	if (hsize > 1000000)
		hsize = 8192;

	sz = sizeof(struct xt_ratelimit_htable) + sizeof(struct hlist_head) * hsize;
	if (sz <= PAGE_SIZE)
		ht = kzalloc(sz, GFP_KERNEL);
	else
		ht = vzalloc(sz);
	if (ht == NULL)
		return -ENOMEM;
	minfo->ht = ht;

	for (i = 0; i < hsize; i++)
		INIT_HLIST_HEAD(&ht->hash[i]);

	ht->size = hsize;
	ht->use = 1;
	ht->mt_count = 0;
	ht->ent_count = 0;
	bitmap_zero(ht->prefix_bitmap, NUM_PREFIX);
	for (i = 0; i < NUM_PREFIX; i++)
		ht->prefix_count[i] = 0;
	strcpy(ht->name, minfo->name);
	spin_lock_init(&ht->lock);
	ht->pde = proc_create_data(minfo->name, 0644, ratelimit_net->ipt_ratelimit,
		    &ratelimit_fops, ht);
	if (ht->pde == NULL) {
		kvfree(ht);
		return -ENOMEM;
	}
	ht->net = net;

	hlist_add_head(&ht->node, &ratelimit_net->htables);

	return 0;
}

static inline u_int32_t
hash_addr(const struct xt_ratelimit_htable *ht, const __be32 addr)
{
	return reciprocal_scale(jhash_1word(addr, 0), ht->size);
}

static inline u_int32_t
hash_addr6(const struct xt_ratelimit_htable *ht, const __be32 addr[])
{
	return reciprocal_scale(jhash2(addr, 4, 0), ht->size);
}

/* get (car) entity by address */
static inline struct ratelimit_ent *
ratelimit_match_find(const struct xt_ratelimit_htable *ht, const __be32 addr, const u8 prefix)
{
	const __be32 mask = htonl(bits2mask(prefix));
	const __be32 addr_masked = addr & mask;
	const u_int32_t hash = hash_addr(ht, addr_masked);

	if (!hlist_empty(&ht->hash[hash])) {
		struct ratelimit_match *mt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
		struct hlist_node *pos;
#endif
		compat_hlist_for_each_entry_rcu(mt, pos, &ht->hash[hash], node) {
			if (mt->family == AF_INET &&
			    mt->prefix == prefix &&
			    mt->addr.ip == addr_masked)
				return mt->ent;
		}
	}
	return NULL;
}

static inline struct ratelimit_ent *
ratelimit_match_find6(const struct xt_ratelimit_htable *ht, const union nf_inet_addr *addr, const u8 prefix)
{
	union nf_inet_addr mask;
	union nf_inet_addr addr_masked;
	u_int32_t hash;
	unsigned int i;

	set_mask6(&mask, prefix);
	for (i = 0; i < ARRAY_SIZE(addr->ip6); ++i)
		addr_masked.ip6[i] = addr->ip6[i] & mask.ip6[i];
	hash = hash_addr6(ht, addr_masked.ip6);

	if (!hlist_empty(&ht->hash[hash])) {
		struct ratelimit_match *mt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
		struct hlist_node *pos;
#endif
		compat_hlist_for_each_entry_rcu(mt, pos, &ht->hash[hash], node) {
			if (mt->family == AF_INET6 &&
			    mt->prefix == prefix &&
			    !memcmp(&mt->addr, &addr_masked, sizeof(addr->ip6)))
				return mt->ent;
		}
	}
	return NULL;
}

static struct ratelimit_ent *
ratelimit_ent_zalloc(int msize)
{
	struct ratelimit_ent *ent;
	unsigned int sz;

	sz = sizeof(struct ratelimit_ent) + sizeof(struct ratelimit_match) * msize;
	if (sz <= PAGE_SIZE)
		ent = kzalloc(sz, GFP_KERNEL);
	else
		ent = vzalloc(sz);
	/* will not need INIT_HLIST_NODE because matches[] are zeroized */

	return ent;
}

static void ratelimit_ent_free_rcu(struct rcu_head *head)
{
	struct ratelimit_ent *ent = container_of(head, struct ratelimit_ent, rcu);

	kvfree(ent);
}

/* side effect: changes ent->mtcnt, thus, breaking its meaning;
 * so, should only be used on ent destrution, and never iterate over
 * live ent->mtcnt */
static void ratelimit_match_free(struct xt_ratelimit_htable *ht,
    struct ratelimit_match *mt)
	/* htable_cleanup, under ratelimit_mutex */
	/* under ht->lock */
{
	struct ratelimit_ent *ent = mt->ent;
	const unsigned int max_prefix = (mt->family == AF_INET6)? MAX_PREFIX6 : MAX_PREFIX4;

	hlist_del_rcu(&mt->node);
	BUG_ON(ht->mt_count == 0);
	--ht->mt_count;

	if (--ht->prefix_count[mt->prefix] == 0)
		clear_bit(max_prefix - mt->prefix, ht->prefix_bitmap);

	BUG_ON(ent->mtcnt == 0);
	if (--ent->mtcnt == 0) {
		/* ent is linked to hash table only from matches,
		 * deallocate ent if no matches are linked */
		call_rcu(&ent->rcu, ratelimit_ent_free_rcu);

		BUG_ON(ht->ent_count == 0);
		ht->ent_count--;
	}
}

/* destroy linked content of hash table */
static void htable_cleanup(struct xt_ratelimit_htable *ht)
	/* under ratelimit_mutex */
{
	unsigned int i;

	for (i = 0; i < ht->size; i++) {
		struct ratelimit_match *mt;
		struct hlist_node *n;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
		struct hlist_node *pos;
#endif

		spin_lock(&ht->lock);
		compat_hlist_for_each_entry_safe(mt, pos, n, &ht->hash[i], node) {
			ratelimit_match_free(ht, mt);
		}
		spin_unlock(&ht->lock);
		cond_resched();
	}
}

/* remove ratelimit entry, called from proc interface */
static void ratelimit_ent_del(struct xt_ratelimit_htable *ht,
    struct ratelimit_ent *ent)
	/* under ht->lock */
{
	int i;

	/* ratelimit_match_free() changes ent->mtcnt */
	for (i = ent->mtcnt; i; )
		ratelimit_match_free(ht, &ent->matches[--i]);
}

static void ratelimit_table_flush(struct xt_ratelimit_htable *ht)
{
	mutex_lock(&ratelimit_mutex);
	htable_cleanup(ht);
	mutex_unlock(&ratelimit_mutex);
}

/* register entry into hash table */
static void ratelimit_ent_add(struct xt_ratelimit_htable *ht,
    struct ratelimit_ent *ent)
	/* under ht->lock */
{
	int i;

	/* add each match address into htable hash */
	for (i = 0; i < ent->mtcnt; i++) {
		struct ratelimit_match *mt = &ent->matches[i];
		const u_int32_t hash = (mt->family == AF_INET6) ?
			hash_addr6(ht, mt->addr.ip6) : hash_addr(ht, mt->addr.ip);
		const unsigned int max_prefix = (mt->family == AF_INET6)? MAX_PREFIX6 : MAX_PREFIX4;

		hlist_add_head_rcu(&mt->node, &ht->hash[hash]);
		ht->mt_count++;
		/* mark bits in reverse order, because I need to search
		 * from highest mask to lowest */
		if (++ht->prefix_count[mt->prefix] == 1)
			set_bit(max_prefix - mt->prefix, ht->prefix_bitmap);
	}
	ht->ent_count++;
}

static void htable_destroy(struct xt_ratelimit_htable *ht)
	/* caller htable_put, iptables rule deletion chain */
	/* under ratelimit_mutex */
{
	struct ratelimit_net *ratelimit_net = ratelimit_pernet(ht->net);
	int i;

	/* ratelimit_net_exit() can independently unregister
	 * proc entries */
	if (ratelimit_net->ipt_ratelimit) {
		remove_proc_entry(ht->name, ratelimit_net->ipt_ratelimit);
	}

	htable_cleanup(ht);
	BUG_ON(ht->mt_count != 0);
	BUG_ON(ht->ent_count != 0);
	BUG_ON(!bitmap_empty(ht->prefix_bitmap, NUM_PREFIX));
	for (i = 0; i < NUM_PREFIX; i++)
		BUG_ON(ht->prefix_count[i]);
	kvfree(ht);
}

/* allocate htable caused by match rule insertion with iptables */
static int htable_get(struct net *net,
    struct xt_ratelimit_mtinfo *minfo)
	/* iptables rule addition chain */
	/* under ratelimit_mutex */
{
	struct ratelimit_net *ratelimit_net = ratelimit_pernet(net);
	struct xt_ratelimit_htable *ht;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *pos;
#endif

	compat_hlist_for_each_entry(ht, pos, &ratelimit_net->htables, node) {
		if (!strcmp(minfo->name, ht->name)) {
			ht->use++;
			minfo->ht = ht;
			return 0;
		}
	}
	return htable_create(net, minfo);
}

/* remove htable caused by match rule deletion with iptables */
static void htable_put(struct xt_ratelimit_htable *ht)
	/* caller ratelimit_mt_destroy, iptables rule deletion */
	/* under ratelimit_mutex */
{
	if (--ht->use == 0) {
		hlist_del(&ht->node);
		htable_destroy(ht);
	}
}

#ifdef RATE_ESTIMATOR
void rate_estimator(struct ratelimit_stat *stat, const unsigned int est_slot, const unsigned int bytes) {
	if (likely(stat->est_slot == est_slot)) {
		/* while we are in 'current time slot' increment traffic counter */
		stat->cur_s_bytes += bytes;
	} else { /* new time slot */
		if (stat->est_slot == (est_slot - 1)) /* adjacent slot */
			stat->prev_s_bytes = stat->cur_s_bytes;
		else
			stat->prev_s_bytes = 0;
		stat->cur_s_bytes = 0;
		stat->est_slot = est_slot;
	}
}
#endif

/* match the packet */
static bool
ratelimit_mt(const struct sk_buff *skb, struct xt_action_param *par)
	/* under bh */
{
	const struct xt_ratelimit_mtinfo *mtinfo = par->matchinfo;
	struct xt_ratelimit_htable *ht = mtinfo->ht;
	struct ratelimit_ent *ent = NULL;
	const unsigned long now = jiffies;
	union nf_inet_addr addr;
	const u8 family = xt_family(par);
	int invprefix;
	int match = false; /* no match, no drop */

	if (unlikely(family == NFPROTO_IPV6)) {
		const struct ipv6hdr *iph = ipv6_hdr(skb);
		memcpy(addr.ip6, (mtinfo->mode & XT_RATELIMIT_DST) ?
		    &iph->daddr : &iph->saddr, sizeof(addr.ip6));
	} else {
		const struct iphdr *iph = ip_hdr(skb);
		addr.ip = (mtinfo->mode & XT_RATELIMIT_DST) ?
			iph->daddr : iph->saddr;
	}

	rcu_read_lock();
	/* first match from longest prefix upwards */
	if (unlikely(family == NFPROTO_IPV6)) {
		for_each_set_bit(invprefix, ht->prefix_bitmap, NUM_PREFIX6) {
			if ((ent = ratelimit_match_find6(ht, &addr, MAX_PREFIX6 - invprefix)))
				break;
		}
	} else {
		for_each_set_bit(invprefix, ht->prefix_bitmap, NUM_PREFIX4) {
			if ((ent = ratelimit_match_find(ht, addr.ip, MAX_PREFIX4 - invprefix)))
				break;
		}
	}
	if (ent) {
		struct ratelimit_car *car = &ent->car;
		const unsigned int len = skb->len; /* L3 */
		u32 tok;

		spin_lock_bh(&ent->lock_bh);
		tok = (now - car->last) * car->cir;
		car->tc += len;
		if (tok) {
			car->tc -= min(tok, car->tc);
			car->last = now;
		}
		if (car->tc > car->cbs) { /* extended burst */
			car->te += car->tc - car->cbs;
			if (car->te > car->ebs) {
				car->te = 0;
				car->tc -= len;
				match = true; /* match is drop */
			}
		}

#ifdef RATE_ESTIMATOR
		if (!match) {
			rate_estimator(&ent->stat, now / RATEST_JIFFIES, len);
		}
#endif
		spin_unlock_bh(&ent->lock_bh);

		if (match) {
			atomic64_add(len, &ent->stat.red_bytes);
			atomic_inc(&ent->stat.red_pkt);
		} else {
			atomic64_add(len, &ent->stat.green_bytes);
			atomic_inc(&ent->stat.green_pkt);
		}
	} else {
		if (ht->other == OT_MATCH)
			match = true; /* match is drop */
		else if (ht->other == OT_HOTDROP)
			par->hotdrop = true;
	}

	rcu_read_unlock();
	return match;
}

/* check and init match rule, allocating htable */
static int ratelimit_mt_check(const struct xt_mtchk_param *par)
	/* iptables rule addition chain */
{
	struct net *net = par->net;
	struct xt_ratelimit_mtinfo *mtinfo = par->matchinfo;
	int ret;

	if (mtinfo->name[sizeof(mtinfo->name) - 1] != '\0')
		return -EINVAL;

	mutex_lock(&ratelimit_mutex);
	ret = htable_get(net, mtinfo);
	mutex_unlock(&ratelimit_mutex);
	return ret;
}

/* remove iptables match rule */
static void ratelimit_mt_destroy(const struct xt_mtdtor_param *par)
	/* iptables rule deletion chain */
{
	const struct xt_ratelimit_mtinfo *mtinfo = par->matchinfo;

	mutex_lock(&ratelimit_mutex);
	htable_put(mtinfo->ht);
	mutex_unlock(&ratelimit_mutex);
}

static struct xt_match ratelimit_mt_reg[] __read_mostly = {
	{
		.name		= "ratelimit",
		.family		= NFPROTO_UNSPEC,
		.match		= ratelimit_mt,
		.matchsize	= sizeof(struct xt_ratelimit_mtinfo),
		.checkentry	= ratelimit_mt_check,
		.destroy 	= ratelimit_mt_destroy,
		.me		= THIS_MODULE,
	},
};

/* AA */
/* net creation/destruction callbacks */
static int __net_init ratelimit_net_init(struct net *net)
{
        struct ratelimit_net *ratelimit_net = ratelimit_pernet(net);

        INIT_HLIST_HEAD(&ratelimit_net->htables);
	ratelimit_net->ipt_ratelimit = proc_mkdir("ipt_ratelimit", net->proc_net);
	if (!ratelimit_net->ipt_ratelimit)
		return -ENOMEM;
        return 0;
}

/* unregister all htables from this net */
static void __net_exit ratelimit_net_exit(struct net *net)
{
	struct ratelimit_net *ratelimit_net = ratelimit_pernet(net);
	struct xt_ratelimit_htable *ht;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *pos;
#endif

	mutex_lock(&ratelimit_mutex);
	compat_hlist_for_each_entry(ht, pos, &ratelimit_net->htables, node)
		remove_proc_entry(ht->name, ratelimit_net->ipt_ratelimit);
	ratelimit_net->ipt_ratelimit = NULL; /* for htable_destroy() */
	mutex_unlock(&ratelimit_mutex);

	remove_proc_entry("ipt_ratelimit", net->proc_net); /* dir */
}

static struct pernet_operations ratelimit_net_ops = {
        .init   = ratelimit_net_init,
        .exit   = ratelimit_net_exit,
        .id     = &ratelimit_net_id,
        .size   = sizeof(struct ratelimit_net),
};

static int __init ratelimit_mt_init(void)
{
        int err;

        err = register_pernet_subsys(&ratelimit_net_ops);
        if (err)
                return err;
        err = xt_register_matches(ratelimit_mt_reg, ARRAY_SIZE(ratelimit_mt_reg));
        if (err)
                unregister_pernet_subsys(&ratelimit_net_ops);
	pr_info(XT_RATELIMIT_VERSION " load %s.\n", err? "error" : "success");
        return err;
}

static void __exit ratelimit_mt_exit(void)
{
	pr_info("unload.\n");
        xt_unregister_matches(ratelimit_mt_reg, ARRAY_SIZE(ratelimit_mt_reg));
        unregister_pernet_subsys(&ratelimit_net_ops);
}

module_init(ratelimit_mt_init);
module_exit(ratelimit_mt_exit);
