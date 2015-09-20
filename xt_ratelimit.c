/*
 * An implementation of commited access rate for Linux iptables
 * (c) 2015 <abc@telekom.ru>
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
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include "compat.h"
#include "xt_ratelimit.h"

MODULE_AUTHOR("<abc@telekom.ru>");
MODULE_DESCRIPTION("iptables ratelimit policer mt module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_ALIAS("ipt_ratelimit");

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
	u32 tc;				/* commited token bucket counter */
	u32 te;				/* exceeded token bucket counter */

	u32 cbs;			/* commited burst size (bytes) */
	u32 ebs;			/* extended burst size (bytes) */
	u32 cir;			/* commited information rate (bits/s) */
};

struct ratelimit_stat {
	u64 green_bytes;
	u64 red_bytes;
	u32 green_pkt;
	u32 red_pkt;
#ifdef DEBUG
	unsigned long first;		/* first time seen */
#endif
};

/* hash bucket entity */
struct ratelimit_match {
	struct hlist_node node;		/* hash bucket list */
	__be32 addr;
	struct ratelimit_ent *ent;	/* owner */
};

/* set enitiy: can have many IPs */
struct ratelimit_ent {
	struct rcu_head rcu;		/* destruction call list */
	int mtcnt;			/* size of matches[mtcnt] */
	struct ratelimit_stat stat;
	struct ratelimit_car car;
	spinlock_t lock_bh;

		/* variable sized array for actual hash entries, it's
		 * to optimize memory allocation and data locality
		 * (without too much hope, though, becasue car and stat
		 * structs are too big to fit into same cache line */
	struct ratelimit_match matches[0];
};

/* per-net named hash table, locked with ratelimit_mutex */
struct xt_ratelimit_htable {
	struct hlist_node node;		/* all htables */
	int use;			/* references from iptables */
	spinlock_t lock;		/* write access to hash */
	unsigned int mt_count;		/* currently matches in the hash */
	unsigned int ent_count;		/* currently entities linked */
	unsigned int size;		/* hash array size */
	struct net *net;		/* for destruction */
	struct proc_dir_entry *pde;
	char name[XT_RATELIMIT_NAME_LEN];
	struct hlist_head hash[0];	/* rcu lists array[size] of ratelimit_match'es */
};

static int ratelimit_net_id;
/* return pointer to per-net-namespace struct */
static inline struct ratelimit_net *ratelimit_pernet(struct net *net)
{
        return net_generic(net, ratelimit_net_id);
}

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
		seq_printf(s, "%s%pI4",
		    i == 0? "" : ",",
		    &ent->matches[i].addr);
	}
	seq_printf(s, " cir %u cbs %u ebs %u;",
	    ent->car.cir, ent->car.cbs, ent->car.ebs);

	seq_printf(s, " tc %u te %u last", ent->car.tc, ent->car.te);
	if (ent->car.last)
		seq_printf(s, " %ld;", jiffies - ent->car.last);
	else
		seq_printf(s, " never;");

	seq_printf(s, " G %u/%llu R %u/%llu",
	    ent->stat.green_pkt,  ent->stat.green_bytes,
	    ent->stat.red_pkt,    ent->stat.red_bytes);

#ifdef DEBUG
	if ((ent->car.last - ent->stat.first) / HZ)
		seq_printf(s, " conf_bps %llu rej_bps %llu",
		    (ent->stat.green_bytes) * 8 /
		    ((ent->car.last - ent->stat.first) / HZ),
		    (ent->stat.red_bytes) * 8 /
		    ((ent->car.last - ent->stat.first) / HZ));
#endif
	seq_printf(s, "\n");

	spin_unlock_bh(&ent->lock_bh);
	return seq_has_overflowed(s);
}

static int ratelimit_seq_show(struct seq_file *s, void *v)
{
	struct xt_ratelimit_htable *ht = s->private;
	unsigned int *bucket = (unsigned int *)v;
	struct ratelimit_match *mt;

	/* print everything from the bucket at once */
	if (!hlist_empty(&ht->hash[*bucket])) {
		hlist_for_each_entry(mt, &ht->hash[*bucket], node)
			if (ratelimit_seq_ent_show(mt, s))
				return -1;
	}
	return 0;
}

static void *ratelimit_seq_start(struct seq_file *s, loff_t *pos)
	__acquires(ht->lock)
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
	__releases(ht->lock)
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

static void ratelimit_table_flush(struct xt_ratelimit_htable *ht);
static struct ratelimit_ent *ratelimit_ent_zalloc(int msize);
static inline struct ratelimit_ent *ratelimit_match_find(const struct xt_ratelimit_htable *ht, const __be32 addr);
static void ratelimit_ent_add(struct xt_ratelimit_htable *ht, struct ratelimit_ent *ent);
static void ratelimit_ent_del(struct xt_ratelimit_htable *ht, struct ratelimit_ent *ent);

static int parse_rule(struct xt_ratelimit_htable *ht, char *str, size_t size)
{
	char * const buf = str;
	const char *p;
	struct ratelimit_ent *ent;
	struct ratelimit_ent *ent_chk;
	__be32 addr;
	int ent_size;
	int add;
	int i;

	if (!size)
		return -EINVAL;

	/* rule format is: +address[,address...] [keyword value]...
	 * address set is unique key for parameters,
	 * address should not duplicate */
	switch (*str) {
		case '\n':
		case '#':
			return 0;
		case '/': /* flush table */
			ratelimit_table_flush(ht);
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

	/* strip trailing newline for better formatting of error messages */
	str[--size] = '\0';
	++str;
	--size;

	/* determine address set size */
	ent_size = 0;
	for (p = str; in4_pton(p, size - (p - str), (u8 *)&addr, -1, &p); ++p) {
		++ent_size;
		if (*p == ' ' || p >= &str[size])
			break;
		else if (*p != ',') {
			pr_err("IP addresses should be separated with ',' (cmd: %s)\n", buf);
			return -EINVAL;
		}
	}
	if (!ent_size) {
		pr_err("Empty IP address list (cmd: %s)\n", buf);
		return -EINVAL;
	}

	/* prepare ent */
	ent = ratelimit_ent_zalloc(ent_size);
	if (!ent)
		return -ENOMEM;

	spin_lock_init(&ent->lock_bh);
	for (i = 0, p = str; in4_pton(p, size - (p - str), (u8 *)&addr, -1, &p); ++p, ++i) {
		struct ratelimit_match *mt = &ent->matches[i];
		int j;

		mt->addr = addr;
		mt->ent = ent;
		++ent->mtcnt;
		/* there should not be duplications,
		 * this is also importnat for below test of mtcnt */
		for (j = 0; j < i; ++j)
			if (ent->matches[j].addr == addr) {
				pr_err("Duplicated IP address %pI4 in list (cmd: %s)\n", &addr, buf);
				kvfree(ent);
				return -EINVAL;
			}
		if (*p == ' ' || p >= &str[size])
			break;
	}
	BUG_ON(ent->mtcnt != ent_size);

	/* parse parameters */
	str = (char *)p;
	if (add) /* unindented */
	for (i = 0; *p; ++i) {
		const char *v;
		unsigned int val;

		while (*p == ' ')
			++p;
		v = p;
		while (*p && *p != ' ')
			++p;
		if (v == p) {
			if (i == 0) {
				kvfree(ent);
				return -EINVAL;
			} else
				break;
		}
		val = simple_strtoul(v, NULL, 10);
		switch (i) {
			case 0:
				ent->car.cir = val;
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

		tent = ratelimit_match_find(ht, mt->addr);
		if (!ent_chk)
			ent_chk = tent;
		if (tent != ent_chk) {
			/* no operation should reference multiple entries */
			pr_err("IP addresss %pI4 from multiple rules (cmd: %s)\n",
			   &mt->addr,  buf);
			goto unlock_einval;
		}
	}

	if (add) {
		/* add op should not reerence any existing entries */
		if (ent_chk) {
			pr_err("Add op references existing address (cmd: %s)\n", buf);
			goto unlock_einval;
		}
	} else {
		/* delete op should reference something, and its size
		 * should be equal (this is correct, because duplications
		 * inside of set(s) are impossible) */
		if (!ent_chk) {
			pr_err("Del op doesn't reference any existing address (cmd: %s)\n", buf);
			goto unlock_einval;
		}
		if (ent_chk->mtcnt != ent->mtcnt) {
			pr_err("Del op doesn't match other rule set fully (cmd: %s)\n", buf);
			goto unlock_einval;
		}
	}

	if (add) {
		ratelimit_ent_add(ht, ent);
		ent = NULL;
	} else
		ratelimit_ent_del(ht, ent_chk);
	spin_unlock(&ht->lock);

	if (ent)
		kvfree(ent);
	return 0;

unlock_einval:
	spin_unlock(&ht->lock);
	kvfree(ent);
	return -EINVAL;
}

static ssize_t
ratelimit_proc_write(struct file *file, const char __user *input,
    size_t size, loff_t *loff)
{
	char buf[1024];
	struct xt_ratelimit_htable *ht = PDE_DATA(file_inode(file));
	char *p;

	pr_info("write:  in %p size %lu off %llu\n", input, size, *loff);
	if (!size)
		return 0;
	if (size > sizeof(buf))
		size = sizeof(buf);
	if (copy_from_user(buf, input, size) != 0)
		return -EFAULT;

	pr_info("write: buf %p size %lu off %llu\n", buf, size, *loff);
	for (p = buf; p < &buf[size]; ) {
		char *str = p;

		while (p < &buf[size] && *p != '\n')
			++p;
		if (*p != '\n') {
			/* untermianted command */
			if (str == buf) {
				pr_err("Rule should end with '\\n'\n");
				pr_info("buf %p str %p p %p size %lu\n", buf, str, p, size);
				return -EINVAL;
			} else {
				p = str;
				break;
			}
		}
		++p;
		if (parse_rule(ht, str, p - str))
			return -EINVAL;
	}

	*loff += p - buf;
	pr_info("    ret size %lu off %llu\n", p - buf, *loff);
	return p - buf;
}

static const struct file_operations ratelimit_fops = {
	.owner		= THIS_MODULE,
	.open		= ratelimit_proc_open,
	.read		= seq_read,
	.write		= ratelimit_proc_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* allocate named hash table, register its proc entry */
static int htable_create(struct net *net, struct xt_ratelimit_mtinfo *minfo)
	/* rule insertion chain, under ratelimit_mutex */
{
        struct ratelimit_net *ratelimit_net = ratelimit_pernet(net);
        struct xt_ratelimit_htable *ht;
        unsigned int hsize = hashsize; /* (entities) */
	unsigned int sz; /* (bytes) */
	int i;

	if (hsize < 0 || hsize > 1000000)
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

/* get (car) entity by address */
static inline struct ratelimit_ent *
ratelimit_match_find(const struct xt_ratelimit_htable *ht,
    const __be32 addr)
{
	const u_int32_t hash = hash_addr(ht, addr);

	if (!hlist_empty(&ht->hash[hash])) {
		struct ratelimit_match *mt;

		hlist_for_each_entry_rcu(mt, &ht->hash[hash], node)
			if (mt->addr == addr)
				return mt->ent;
	}
	return NULL;
}
static struct ratelimit_ent *
ratelimit_match_find_lock(const struct xt_ratelimit_htable *ht,
    const __be32 addr)
	/* under rcu bh */
{
	struct ratelimit_ent *ent = ratelimit_match_find(ht, addr);

	if (ent)
		spin_lock(&ent->lock_bh);
	return ent;
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

	pr_debug("ratelimit_ent_free_rcu ent=%p\n", ent);
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

	pr_debug(" ratelimit_match_free IN: ent->mtcnt %d, ht->ent_count, %d, ht->mt_count %d\n",
	    ent->mtcnt, ht->ent_count, ht->mt_count);

	pr_debug(" ratelimit_match_free next hlist_del_rcu %p [%p %p]\n", &mt->node, mt->node.next, mt->node.pprev);
	hlist_del_rcu(&mt->node);
	pr_debug(" ratelimit_match_free after hlist_del_rcu, next BUG_ON %d\n", ht->mt_count);
	BUG_ON(ht->mt_count == 0);
	--ht->mt_count;

	pr_debug(" ratelimit_match_free next BUG_ON %d, if\n", ent->mtcnt);
	BUG_ON(ent->mtcnt == 0);
	if (--ent->mtcnt == 0) {
		/* ent is linked to hash table only from matches,
		 * deallocate ent if no matches are linked */
		pr_debug(" ratelimit_match_free call call_rcu\n");
		call_rcu(&ent->rcu, ratelimit_ent_free_rcu);

		pr_debug(" ratelimit_match_free BUG_ON %d\n", ht->ent_count);
		BUG_ON(ht->ent_count == 0);
		pr_debug(" ratelimit_match_free ht->ent_count--\n");
		ht->ent_count--;
	}
	pr_debug(" ratelimit_match_free OUT: ht->ent_count, %d, ht->mt_count %d\n",
	    ht->ent_count, ht->mt_count);
}

/* destroy linked content of hash table */
static void htable_cleanup(struct xt_ratelimit_htable *ht)
	/* under ratelimit_mutex */
{
	unsigned int i;

	pr_debug("htable_cleanup IN [%d]\n", ht->size);
	for (i = 0; i < ht->size; i++) {
		struct ratelimit_match *mt;
		struct hlist_node *n;

		spin_lock(&ht->lock);
		hlist_for_each_entry_safe(mt, n, &ht->hash[i], node) {
			ratelimit_match_free(ht, mt);
		}
		spin_unlock(&ht->lock);
		cond_resched();
	}
	pr_debug("htable_cleanup OUT\n");
}

/* remove ratelimit entry, called from proc interface */
static void ratelimit_ent_del(struct xt_ratelimit_htable *ht,
    struct ratelimit_ent *ent)
	/* under ht->lock */
{
	int i;

	pr_debug("ratelimit_ent_del IN ent=%p, ent->mtcnt %d\n", ent, ent->mtcnt);
	/* ratelimit_match_free() changes ent->mtcnt */
	for (i = ent->mtcnt; i; )
		ratelimit_match_free(ht, &ent->matches[--i]);
	pr_debug("ratelimit_ent_del OUT\n");
}

static void ratelimit_table_flush(struct xt_ratelimit_htable *ht)
{
	pr_debug("ratelimit_table_flush IN\n");
	mutex_lock(&ratelimit_mutex);
	htable_cleanup(ht);
	mutex_unlock(&ratelimit_mutex);
	pr_debug("ratelimit_table_flush OUT\n");
}

/* register entry into hash table */
static void ratelimit_ent_add(struct xt_ratelimit_htable *ht,
    struct ratelimit_ent *ent)
	/* under ht->lock */
{
	int i;

	pr_debug("ratelimit_ent_add IN: ent=%p\n", ent);
	/* add each match address into htable hash */
	for (i = 0; i < ent->mtcnt; i++) {
		struct ratelimit_match *mt = &ent->matches[i];

		pr_debug("hlist_add_head_rcu %p\n", &mt->node);
		hlist_add_head_rcu(&mt->node, &ht->hash[hash_addr(ht, mt->addr)]);
		ht->mt_count++;
	}
	ht->ent_count++;
	pr_debug("ratelimit_ent_add OUT: ent=%p\n", ent);
}

static void htable_destroy(struct xt_ratelimit_htable *ht)
	/* caller htable_put, iptables rule deletion chain */
	/* under ratelimit_mutex */
{
	struct ratelimit_net *ratelimit_net = ratelimit_pernet(ht->net);

	pr_debug("htable_destroy IN: ent_count %d, mt_count %d\n", ht->ent_count, ht->mt_count);
	/* ratelimit_net_exit() can independently unregister
	 * proc entries */
	if (ratelimit_net->ipt_ratelimit) {
		pr_debug("remove_proc_entry call, %s\n", ht->name);
		remove_proc_entry(ht->name, ratelimit_net->ipt_ratelimit);
		pr_debug("remove_proc_entry return\n");
	}

	pr_debug("htable_destroy call htable_cleanup\n");
	htable_cleanup(ht);
	BUG_ON(ht->mt_count != 0);
	BUG_ON(ht->ent_count != 0);
	pr_debug("htable_destroy OUT: ent_count %d, mt_count %d\n", ht->ent_count, ht->mt_count);
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

	hlist_for_each_entry(ht, &ratelimit_net->htables, node) {
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
	pr_debug("htable_put IN, use %d\n", ht->use);
	if (--ht->use == 0) {
		hlist_del(&ht->node);
		htable_destroy(ht);
	}
	pr_debug("htable_put OUT\n");
}

/* match the packet */
static bool
ratelimit_mt(const struct sk_buff *skb, struct xt_action_param *par)
	/* under bh */
{
	const struct xt_ratelimit_mtinfo *mtinfo = par->matchinfo;
	struct xt_ratelimit_htable *ht = mtinfo->ht;
	struct ratelimit_ent *ent;
	const unsigned long now = jiffies;
	__be32 addr;
	int match = false; /* no match, no drop */

	if (mtinfo->mode & XT_RATELIMIT_DST)
		addr = ip_hdr(skb)->daddr;
	else
		addr = ip_hdr(skb)->saddr;

	rcu_read_lock();
	ent = ratelimit_match_find_lock(ht, addr);
	if (ent) {
		struct ratelimit_car *car = &ent->car;
		const unsigned int len = skb->len; /* L3 */
		const unsigned long delta_ms = (now - car->last) * (MSEC_PER_SEC / HZ);

		car->tc += len;
		if (delta_ms) {
			const u32 tok = delta_ms * (car->cir / (BITS_PER_BYTE * MSEC_PER_SEC));

			car->tc -= min(tok, car->tc);
#ifdef DEBUG
			if (!ent->stat.first)
				ent->stat.first = now;
#endif
			car->last = now;
		}
		if (car->tc > car->cbs) { /* extended burst */
			car->te += car->tc - car->cbs;
			if (car->te > car->ebs) {
				car->te = 0;
				match = true; /* match is drop */
			}
		}
		if (match) {
			ent->stat.red_bytes += len;
			ent->stat.red_pkt++;
			car->tc -= len;
		} else {
			ent->stat.green_bytes += len;
			ent->stat.green_pkt++;
		}
		spin_unlock(&ent->lock_bh);
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

	pr_debug("ratelimit_mt_check\n");
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

	pr_debug("ratelimit_mt_destroy\n");
	mutex_lock(&ratelimit_mutex);
	htable_put(mtinfo->ht);
	mutex_unlock(&ratelimit_mutex);
}

static struct xt_match ratelimit_mt_reg[] __read_mostly = {
	{
		.name		= "ratelimit",
		.family		= NFPROTO_IPV4,
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

	mutex_lock(&ratelimit_mutex);
	hlist_for_each_entry(ht, &ratelimit_net->htables, node)
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

	pr_debug("ratelimit_mt_init\n");
        err = register_pernet_subsys(&ratelimit_net_ops);
        if (err)
                return err;
        err = xt_register_matches(ratelimit_mt_reg, ARRAY_SIZE(ratelimit_mt_reg));
        if (err)
                unregister_pernet_subsys(&ratelimit_net_ops);
        return err;
}

static void __exit ratelimit_mt_exit(void)
{
	pr_debug("ratelimit_mt_exit\n");
        xt_unregister_matches(ratelimit_mt_reg, ARRAY_SIZE(ratelimit_mt_reg));
        unregister_pernet_subsys(&ratelimit_net_ops);
}

module_init(ratelimit_mt_init);
module_exit(ratelimit_mt_exit);
