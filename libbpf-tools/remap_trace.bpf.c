/*
 * Create: Tue Nov 11 16:04:26 2025
 */
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "remap_trace.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES 65536

struct file_info {
	struct file *file;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} args_int_int_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_STACK_TRACE);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u64) * PERF_MAX_STACK_DEPTH);
        __uint(max_entries, MAX_ENTRIES);
} stackmap SEC(".maps");

/* perf event buf, used to send data to user space */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct page___new {
        struct mem_cgroup *mem_cgroup;
} __attribute__((preserve_access_index));

struct page___old {
        long memcg_data;
} __attribute__((preserve_access_index));

static __always_inline void* get_memcg(struct page *page)
{
        struct page___new *new = (void *)page;

        if (bpf_core_field_exists(new->mem_cgroup)) {
                return BPF_CORE_READ(new, mem_cgroup);
        } else {
                struct page___old *old = (void *)page;

                return (void *)BPF_CORE_READ(old, memcg_data);
        }
}

static __always_inline struct inode *page_to_inode(struct page *page)
{

	struct address_space *mapping;
	struct inode *inode;
	u16 mode;

	if (bpf_probe_read(&mapping, 8, &page->mapping))
		return NULL;
	/*
	 * The reverse mapping of anonymous pages utilizes the two
	 * lower bits, so filtering is applied here
	 */

	if ((u64)mapping & 3)
		return NULL;
	if (bpf_probe_read(&inode, 8, &mapping->host))
		return NULL;
	if (bpf_probe_read(&mode, 2, &inode->i_mode))
		return NULL;
	// filter out blkdev file
	if (mode == 0x6000)
		return NULL;

	return inode;
}

static __always_inline struct dentry *inode_to_dentry(struct inode *inode)
{

	struct dentry *dentry = 0;
	void * offset = &dentry->d_u;
	void * alias;

	if (bpf_probe_read(&alias, 8, &inode->i_dentry))
		return NULL;
	if (!alias)
		return NULL;
	dentry = (struct dentry*)(alias - offset);

	return dentry;
}

static __always_inline int cgroup_info(struct mem_cgroup *memcg, struct event *event)
{
        char ebpf[] = "xxx.scope";
        struct cgroup_subsys_state *css = (void*)memcg;
        struct cgroup *cgroup;
        struct kernfs_node *kn;
        struct task_struct *tsk;
        struct css_set *cgroups;
        char *name;
        u64 css1;

        bpf_probe_read(&cgroup, 8, &css->cgroup);
        bpf_probe_read(&kn, 8, &cgroup->kn);
        bpf_probe_read(&name, 8, &kn->name);

        tsk = (void*)bpf_get_current_task();
        bpf_probe_read(&cgroups, 8, &tsk->cgroups);
        if (!cgroups)
                return 1;

	// read mem_cgroup
        bpf_probe_read(&css, 8, (char*)cgroups +32);

        bpf_probe_read(&event->cgroup, 63, name);

        return 0;
}

SEC("kprobe/__remove_mapping")
int remove_mapping(struct pt_regs *ctx)
{
	struct dentry *dentry;
	struct inode *inode;
	struct address_space *mapping = (void *)PT_REGS_PARM1_CORE(ctx);
	struct page *page = (void *)PT_REGS_PARM2_CORE(ctx);
	struct mem_cgroup *memcg;
	struct event e = { 0 };
	char *name;

	memcg = get_memcg(page);

	bpf_probe_read(&inode, 8, &mapping->host);

	dentry = inode_to_dentry(inode);
	if (!dentry)
		return 0;
	e.k_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_FAST_STACK_CMP);
	bpf_probe_read(&name, 8, &dentry->d_name.name);
	bpf_probe_read(&e.file, 63, name);
	bpf_probe_read(&e.index, 8, &page->index);
	bpf_get_current_comm(&e.comm, sizeof(e.comm));
	cgroup_info(memcg, &e);
	e.ts = bpf_ktime_get_ns();

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}
#if 0
SEC("kprobe/submit_bio")
int do_submit_bio(struct pt_regs *ctx)
{
	struct bio *bio = (void *)PT_REGS_PARM1_CORE(ctx);
	struct inode_info *info;
	u64 rchar;
	int bi_size;
	int opf;
	u16 i_mode;
	u64 alias;
	void *name;
	struct bio_vec *bv;
	struct page *page;
	struct inode *inode;
	struct mem_cgroup *memcg;
	struct dentry *dentry = 0;
	struct event e = { 0 };

	if (bpf_probe_read(&opf, 4, &bio->bi_opf))
		return 0;
	/*
	 * Filter out write io
	 */
	if (opf & 1)
		return 0;
	if (bpf_probe_read(&bi_size, 4, &bio->bi_iter.bi_size))
		return 0;
	if (!bi_size)
		return 0;
	if (bpf_probe_read(&bv, 8, &bio->bi_io_vec))
		return 0;
	if (bpf_probe_read(&page, 8, &bv->bv_page))
		return 0;

	memcg = (void*)get_memcg(page);
	if (!memcg)
		return 0;

	inode  = page_to_inode(page);
	if (!inode)
		return 0;;
	dentry = inode_to_dentry(inode);
	if (!dentry)
		return 0;

	e.k_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_FAST_STACK_CMP);
	bpf_probe_read(&name, 8, &dentry->d_name.name);
	bpf_probe_read(&e.file, 63, name);
	bpf_probe_read(&e.index, 8, &page->index);
	e.ts = bpf_ktime_get_ns();

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}
#endif 
