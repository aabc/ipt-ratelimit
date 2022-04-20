#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0) && \
	!(defined(RHEL_MAJOR) && RHEL_MAJOR == 7 && RHEL_MINOR > 2)
static inline bool seq_has_overflowed(struct seq_file *m)
{
	return m->count == m->size;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
void kvfree(const void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#define reciprocal_scale reciprocal_scale_compat
static inline u32 reciprocal_scale(u32 val, u32 ep_ro)
{
	return (u32)(((u64) val * ep_ro) >> 32);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
# define compat_hlist_for_each_entry		hlist_for_each_entry
# define compat_hlist_for_each_entry_safe	hlist_for_each_entry_safe
# define compat_hlist_for_each_entry_rcu	hlist_for_each_entry_rcu
static inline struct inode *file_inode(const struct file *f)
{
  return f->f_path.dentry->d_inode;
}
#else
# define compat_hlist_for_each_entry(a,pos,c,d)	hlist_for_each_entry(a,c,d)
# define compat_hlist_for_each_entry_safe(a,pos,c,d,e)	hlist_for_each_entry_safe(a,c,d,e)
# define compat_hlist_for_each_entry_rcu(a,pos,c,d)	hlist_for_each_entry_rcu(a,c,d)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
# define PDE_DATA(inode) PDE(inode)->data
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
# define PDE_DATA pde_data
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static inline u_int8_t xt_family(const struct xt_action_param *par)
{
		return par->family;
}
#endif
