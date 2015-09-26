#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
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

